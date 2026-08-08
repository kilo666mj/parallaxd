// Command parallaxd is the coordinator.
//
// It is the only component that decides anything: probers observe and report,
// this asks for corroboration when a report says something is down, applies
// the quorum rule, remembers what it has already said, and tells someone.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/coordinator"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

// version is overridden at link time with -X main.version=<tag>.
var version = "dev"

type config struct {
	// Name is what this coordinator signs requests as. Probers verify against
	// it, so it must match their coordinator_name.
	Name string `json:"name"`

	Listen string `json:"listen"`

	// KeyFile holds the coordinator's private key, base64. A file rather than
	// an inline value so it can be deployed with its own permissions.
	KeyFile string `json:"key_file"`

	Probers []proberConfig `json:"probers"`
	Checks  []checkConfig  `json:"checks"`

	// Components group checks into the services a person recognises. Optional:
	// a check in no component alerts on its own, exactly as before.
	Components  []check.Component         `json:"components,omitempty"`
	Maintenance []coordinator.Maintenance `json:"maintenance,omitempty"`
	StateFile   string                    `json:"state_file,omitempty"`
	// OperatorTokenFile enables authenticated incident and silence mutations.
	// Keeping the bearer token out of the JSON makes normal config inspection
	// safe and lets deployment tooling apply tighter file permissions.
	OperatorTokenFile string `json:"operator_token_file,omitempty"`

	// Webhook, when set, receives every alert as JSON in addition to the log.
	Webhook        string            `json:"webhook,omitempty"`
	WebhookHeaders map[string]string `json:"webhook_headers,omitempty"`

	// Heartbeat is the outward dead-man's switch. Without it nothing outside
	// the fleet notices if this coordinator dies, and the resulting silence
	// looks exactly like everything being fine.
	Heartbeat heartbeatConfig `json:"heartbeat,omitempty"`

	// StaleMultiplier and StaleGrace decide how late a check may be before
	// nobody is considered to be watching it: interval*multiplier + grace.
	StaleMultiplier int      `json:"stale_multiplier,omitempty"`
	StaleGrace      duration `json:"stale_grace,omitempty"`
	WatchInterval   duration `json:"watch_interval,omitempty"`

	FanOutTimeout duration `json:"fan_out_timeout,omitempty"`
	RequestTTL    duration `json:"request_ttl,omitempty"`
	ResultMaxAge  duration `json:"result_max_age,omitempty"`
}

type heartbeatConfig struct {
	// URL must point off the fleet — a hosted cron-ping service, or anything
	// that alerts when an expected ping does not arrive. A watcher inside the
	// fleet cannot report the fleet being unreachable.
	URL      string            `json:"url"`
	Interval duration          `json:"interval,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
}

type proberConfig struct {
	Name string `json:"name"`
	URL  string `json:"url"`

	// Provider groups probers sharing a network. Quorum uses it to tell three
	// opinions from one opinion held three times; leaving it blank means a
	// diversity requirement can never be satisfied, which fails closed.
	Provider string `json:"provider"`

	// PublicKey authenticates results from this prober, base64.
	PublicKey string `json:"public_key"`
}

type checkConfig struct {
	Name         string            `json:"name"`
	Kind         check.Kind        `json:"kind"`
	Target       string            `json:"target"`
	Vantage      check.Vantage     `json:"vantage"`
	Interval     duration          `json:"interval"`
	Timeout      duration          `json:"timeout"`
	Quorum       check.Quorum      `json:"quorum"`
	ExpectStatus []int             `json:"expect_status,omitempty"`
	ExpectBody   string            `json:"expect_body,omitempty"`
	Send         string            `json:"send,omitempty"`
	HTTPMethod   string            `json:"http_method,omitempty"`
	HTTPHeaders  map[string]string `json:"http_headers,omitempty"`
	HTTPBody     string            `json:"http_body,omitempty"`
	ServerName   string            `json:"server_name,omitempty"`
	StartTLS     bool              `json:"start_tls,omitempty"`
	DNSRecord    string            `json:"dns_record,omitempty"`

	// Prober is the preferred owner. Empty uses rendezvous hashing; dynamic
	// assignment temporarily moves checks away from unavailable owners.
	Prober string `json:"prober,omitempty"`
}

func (c checkConfig) toCheck() check.Check {
	return check.Check{
		Name: c.Name, Kind: c.Kind, Target: c.Target, Vantage: c.Vantage,
		Interval: time.Duration(c.Interval), Timeout: time.Duration(c.Timeout),
		Quorum: c.Quorum, ExpectStatus: c.ExpectStatus, ExpectBody: c.ExpectBody,
		Send:       c.Send,
		Prober:     c.Prober,
		HTTPMethod: c.HTTPMethod, HTTPHeaders: c.HTTPHeaders, HTTPBody: c.HTTPBody,
		ServerName: c.ServerName, StartTLS: c.StartTLS, DNSRecord: c.DNSRecord,
	}
}

type duration time.Duration

func (d *duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf(`duration must be a string like "30s": %w`, err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = duration(parsed)
	return nil
}

func main() {
	var (
		configPath = flag.String("config", "/etc/parallaxd/coordinator.json", "config file path")
		genKey     = flag.Bool("genkey", false, "generate a keypair and exit")
		debug      = flag.Bool("debug", false, "verbose logging")
		showVer    = flag.Bool("version", false, "print version and exit")
		validate   = flag.Bool("validate", false, "validate config and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("parallaxd", version)
		return
	}
	if *genKey {
		pub, priv, err := wire.GenerateKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, "generate key:", err)
			os.Exit(1)
		}
		fmt.Printf("# private key — write to the coordinator's key_file, mode 0600\n%s\n\n",
			wire.EncodeKey(priv))
		fmt.Printf("# public key — set as coordinator_key on every prober\n%s\n",
			wire.EncodeKey(pub))
		return
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)
	if *validate {
		if err := validateConfig(*configPath, log); err != nil {
			log.Error("invalid configuration", "err", err)
			os.Exit(1)
		}
		fmt.Printf("%s: valid\n", *configPath)
		return
	}

	if err := run(*configPath, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(configPath string, log *slog.Logger) error {
	cfg, c, err := prepare(configPath, log, true)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The dead-man's switch: an outward heartbeat so something off the fleet
	// notices if this dies, and an inward watch so a prober that goes quiet is
	// reported rather than silently stopping its checks.
	watchdogDone := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		c.Run(ctx)
	}()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           c.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}

	errs := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen, "coordinator", cfg.Name,
			"probers", len(cfg.Probers), "checks", len(cfg.Checks),
			"components", len(cfg.Components), "version", version)
		for prober, assigned := range c.Assignments() {
			log.Info("assignment", "prober", prober, "checks", assigned)
		}
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	<-watchdogDone
	// A verdict already being worked on gets to finish and be delivered,
	// rather than being abandoned halfway through an alert.
	c.Wait()
	return nil
}

// validateConfig exercises the same parsing, key loading, and coordinator
// construction as startup without restoring mutable state or starting any
// network activity. Deployment tooling can therefore reject a candidate
// before replacing the running configuration.
func validateConfig(configPath string, log *slog.Logger) error {
	_, _, err := prepare(configPath, log, false)
	return err
}

func prepare(configPath string, log *slog.Logger, restoreState bool) (config, *coordinator.Coordinator, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return config{}, nil, err
	}

	rawKey, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return config{}, nil, fmt.Errorf("read key file: %w", err)
	}
	key, err := wire.DecodePrivateKey(strings.TrimSpace(string(rawKey)))
	if err != nil {
		return config{}, nil, err
	}
	var operatorToken string
	if cfg.OperatorTokenFile != "" {
		rawToken, err := os.ReadFile(cfg.OperatorTokenFile)
		if err != nil {
			return config{}, nil, fmt.Errorf("read operator token file: %w", err)
		}
		operatorToken = strings.TrimSpace(string(rawToken))
		if operatorToken == "" {
			return config{}, nil, errors.New("operator token file is empty")
		}
	}

	peers := make([]coordinator.Peer, 0, len(cfg.Probers))
	for _, p := range cfg.Probers {
		pub, err := wire.DecodePublicKey(p.PublicKey)
		if err != nil {
			return config{}, nil, fmt.Errorf("prober %q: %w", p.Name, err)
		}
		peers = append(peers, coordinator.Peer{
			Name: p.Name, URL: p.URL, Provider: p.Provider, PublicKey: pub,
		})
	}

	checks := make([]check.Check, 0, len(cfg.Checks))
	for _, c := range cfg.Checks {
		checks = append(checks, c.toCheck())
	}

	// The log always gets the alert. A webhook is additional, so a webhook
	// that is down costs the integration and not the record.
	var notifier coordinator.Notifier = coordinator.LogNotifier{Logger: log}
	if cfg.Webhook != "" {
		notifier = coordinator.Notifiers{
			coordinator.LogNotifier{Logger: log},
			coordinator.WebhookNotifier{URL: cfg.Webhook, Headers: cfg.WebhookHeaders},
		}
	}

	stateFile := cfg.StateFile
	if !restoreState {
		stateFile = ""
	}
	c, err := coordinator.New(coordinator.Config{
		Name: cfg.Name, Key: key, Peers: peers, Checks: checks,
		Components:    cfg.Components,
		Maintenance:   cfg.Maintenance,
		StateFile:     stateFile,
		OperatorToken: operatorToken,
		Notifier:      notifier,
		Heartbeat: coordinator.Heartbeat{
			URL:      cfg.Heartbeat.URL,
			Interval: time.Duration(cfg.Heartbeat.Interval),
			Headers:  cfg.Heartbeat.Headers,
		},
		StaleMultiplier: cfg.StaleMultiplier,
		StaleGrace:      time.Duration(cfg.StaleGrace),
		WatchInterval:   time.Duration(cfg.WatchInterval),
		FanOutTimeout:   time.Duration(cfg.FanOutTimeout),
		RequestTTL:      time.Duration(cfg.RequestTTL),
		ResultMaxAge:    time.Duration(cfg.ResultMaxAge),
		Logger:          log,
	})
	if err != nil {
		return config{}, nil, err
	}
	return cfg, c, nil
}

func loadConfig(path string) (config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return config{}, fmt.Errorf("read config: %w", err)
	}
	cfg := config{Listen: "127.0.0.1:8972", Name: "coordinator"}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return config{}, errors.New("parse config: trailing JSON value")
	}

	switch {
	case strings.TrimSpace(cfg.KeyFile) == "":
		return config{}, errors.New("key_file is required")
	case len(cfg.Probers) == 0:
		return config{}, errors.New("at least one prober is required")
	}
	for _, p := range cfg.Probers {
		switch {
		case strings.TrimSpace(p.Name) == "":
			return config{}, errors.New("every prober needs a name")
		case strings.TrimSpace(p.URL) == "":
			return config{}, fmt.Errorf("prober %q: url is required", p.Name)
		case strings.TrimSpace(p.PublicKey) == "":
			return config{}, fmt.Errorf("prober %q: public_key is required — without it "+
				"its results cannot be authenticated and anything could vote as it", p.Name)
		}
	}
	return cfg, nil
}
