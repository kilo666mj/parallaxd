// Command parallaxd-probe is the prober agent.
//
// It runs the checks it is assigned, answers signed corroboration requests,
// and signs everything it reports. It decides nothing: whether a target is
// down, whether enough probers agree, and whether anyone needs telling all
// belong to the coordinator.
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
	"github.com/kilo666mj/parallaxd/internal/probe"
	"github.com/kilo666mj/parallaxd/internal/prober"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

// version is overridden at link time with -X main.version=<tag>.
var version = "dev"

type config struct {
	// Name identifies this prober fleet-wide. Quorum counts one vote per
	// name, so a duplicate would let two hosts vote as one — or one host vote
	// twice, depending on which way the mistake ran.
	Name string `json:"name"`

	// Provider groups probers sharing a network, so a quorum can tell three
	// opinions from one opinion held three times.
	Provider string `json:"provider"`

	Listen string `json:"listen"`

	// KeyFile holds this prober's private key, base64. A file rather than an
	// inline value so it can be deployed with its own permissions and kept
	// out of anything that gets copied around.
	KeyFile string `json:"key_file"`

	// CoordinatorKey is the coordinator's public key, base64. Requests that
	// do not verify against it never become network traffic.
	CoordinatorKey string `json:"coordinator_key"`

	// CoordinatorName must match the name the coordinator signs as.
	CoordinatorName string `json:"coordinator_name"`

	// CoordinatorURL is where scheduled results are submitted.
	CoordinatorURL string `json:"coordinator_url"`

	// AllowTargets, when set, is the exhaustive list of networks this prober
	// may connect to, as CIDR prefixes or bare addresses. Empty means
	// anywhere the built-in and vantage rules permit — fine for a prober on a
	// public network, wrong for one inside something sensitive.
	AllowTargets []string `json:"allow_targets,omitempty"`

	// DenyTargets is subtracted from whatever AllowTargets permits. Deny
	// wins, so a narrow exclusion inside a broad allowance works.
	DenyTargets []string `json:"deny_targets,omitempty"`

	// Checks assigned to this prober. In steady state only these run here;
	// everything else happens on request. Later this comes from the
	// coordinator, but a static list keeps the first version deployable.
	Checks []checkConfig `json:"checks"`

	// MeshInterval is how often this prober checks whether it can still reach
	// its peers. Zero applies the default; a negative value disables mesh
	// reporting entirely, which means this prober keeps being counted even
	// when it can reach nothing.
	MeshInterval duration `json:"mesh_interval,omitempty"`

	// MeshTimeout bounds a single peer connection. It must stay well under
	// MeshInterval: a cut-off prober spends this on every peer, and if the
	// total exceeds the interval its reports fall behind exactly when they
	// matter most.
	MeshTimeout duration `json:"mesh_timeout,omitempty"`

	AssignmentInterval duration `json:"assignment_interval,omitempty"`
}

// checkConfig is a check with durations written the way a human would.
type checkConfig struct {
	Name             string            `json:"name"`
	Kind             check.Kind        `json:"kind"`
	Target           string            `json:"target"`
	Vantage          check.Vantage     `json:"vantage"`
	Interval         duration          `json:"interval"`
	Timeout          duration          `json:"timeout"`
	Quorum           check.Quorum      `json:"quorum"`
	ExpectStatus     []int             `json:"expect_status,omitempty"`
	ExpectBody       string            `json:"expect_body,omitempty"`
	Send             string            `json:"send,omitempty"`
	HTTPMethod       string            `json:"http_method,omitempty"`
	HTTPHeaders      map[string]string `json:"http_headers,omitempty"`
	HTTPBody         string            `json:"http_body,omitempty"`
	ServerName       string            `json:"server_name,omitempty"`
	StartTLS         bool              `json:"start_tls,omitempty"`
	DNSRecord        string            `json:"dns_record,omitempty"`
	TLSExpiryWarning duration          `json:"tls_expiry_warning,omitempty"`

	// Prober is accepted and ignored here: the coordinator uses it to know who
	// runs what, and a prober templated its own checks does not need telling
	// that they are its own. Present so one check definition can be shared
	// between both configs without either rejecting the other's fields.
	Prober string `json:"prober,omitempty"`
}

func (c checkConfig) toCheck() check.Check {
	return check.Check{
		Name: c.Name, Kind: c.Kind, Target: c.Target, Vantage: c.Vantage,
		Interval: time.Duration(c.Interval), Timeout: time.Duration(c.Timeout),
		Quorum: c.Quorum, ExpectStatus: c.ExpectStatus, ExpectBody: c.ExpectBody,
		Send: c.Send, HTTPMethod: c.HTTPMethod, HTTPHeaders: c.HTTPHeaders,
		HTTPBody: c.HTTPBody, ServerName: c.ServerName, StartTLS: c.StartTLS, DNSRecord: c.DNSRecord,
		TLSExpiryWarning: time.Duration(c.TLSExpiryWarning),
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
		configPath = flag.String("config", "/etc/parallaxd/probe.json", "config file path")
		genKey     = flag.Bool("genkey", false, "generate a keypair and exit")
		debug      = flag.Bool("debug", false, "verbose logging")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("parallaxd-probe", version)
		return
	}
	if *genKey {
		if err := generateKey(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "generate key:", err)
			os.Exit(1)
		}
		return
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	if err := run(*configPath, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// generateKey writes a fresh keypair. The private half goes to a file the
// operator places; the public half goes to the coordinator's config.
func generateKey(w *os.File) error {
	pub, priv, err := wire.GenerateKey()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "# private key — write to the prober's key_file, mode 0600\n%s\n\n",
		wire.EncodeKey(priv))
	fmt.Fprintf(w, "# public key — register with the coordinator\n%s\n", wire.EncodeKey(pub))
	return nil
}

func run(configPath string, log *slog.Logger) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	rawKey, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}
	key, err := wire.DecodePrivateKey(strings.TrimSpace(string(rawKey)))
	if err != nil {
		return err
	}

	coordPub, err := wire.DecodePublicKey(cfg.CoordinatorKey)
	if err != nil {
		return fmt.Errorf("coordinator key: %w", err)
	}
	ring := wire.NewKeyring()
	if err := ring.Add(cfg.CoordinatorName, coordPub); err != nil {
		return err
	}

	allow, err := probe.ParsePrefixes(cfg.AllowTargets)
	if err != nil {
		return fmt.Errorf("allow_targets: %w", err)
	}
	deny, err := probe.ParsePrefixes(cfg.DenyTargets)
	if err != nil {
		return fmt.Errorf("deny_targets: %w", err)
	}

	p, err := prober.New(prober.Config{
		Name: cfg.Name, Provider: cfg.Provider,
		Key: key, Keyring: ring, CoordinatorName: cfg.CoordinatorName, Logger: log,
		Policy: probe.Policy{Allow: allow, Deny: deny, RequireAllowForInternal: true},
	})
	if err != nil {
		return err
	}
	if len(allow) > 0 {
		log.Info("target allowlist in force", "networks", cfg.AllowTargets)
	}
	if len(deny) > 0 {
		log.Info("target denylist in force", "networks", cfg.DenyTargets)
	}

	checks := make([]check.Check, 0, len(cfg.Checks))
	for _, c := range cfg.Checks {
		checks = append(checks, c.toCheck())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: p.Handler(),
		// A request that has not been verified yet must not be able to hold a
		// connection open indefinitely.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}

	errs := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen, "prober", cfg.Name,
			"provider", cfg.Provider, "version", version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	resultOut := &submitter{
		url:    strings.TrimRight(cfg.CoordinatorURL, "/") + "/v1/results",
		client: &http.Client{Timeout: 30 * time.Second},
	}
	if cfg.CoordinatorURL != "" {
		log.Info("watching coordinator assignments")
		go p.WatchAssignments(ctx, prober.AssignmentConfig{
			CoordinatorURL: cfg.CoordinatorURL,
			Interval:       time.Duration(cfg.AssignmentInterval),
		}, resultOut)
	} else if len(checks) > 0 {
		log.Info("scheduling static checks", "count", len(checks))
		go p.Schedule(ctx, checks, resultOut)
	} else {
		log.Info("no checks assigned; answering corroboration requests only")
	}

	// The mesh watch is what lets the coordinator tell "I cannot reach this"
	// from "I cannot reach anything". Without it this prober keeps being
	// counted during a partition, which is the failure the whole design is
	// built to remove.
	if cfg.MeshInterval >= 0 {
		go p.WatchMesh(ctx, prober.MeshConfig{
			CoordinatorURL: cfg.CoordinatorURL,
			Interval:       time.Duration(cfg.MeshInterval),
			Timeout:        time.Duration(cfg.MeshTimeout),
		})
	} else {
		log.Warn("mesh reporting disabled; this prober will keep being counted " +
			"even when it can reach nothing")
	}

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// submitter posts signed results to the coordinator.
type submitter struct {
	url    string
	client *http.Client
}

func (s *submitter) Submit(ctx context.Context, env wire.Envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("coordinator returned %s", resp.Status)
	}
	return nil
}

func loadConfig(path string) (config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return config{}, fmt.Errorf("read config: %w", err)
	}
	cfg := config{Listen: "127.0.0.1:8973", CoordinatorName: "coordinator"}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return config{}, errors.New("parse config: trailing JSON value")
	}

	switch {
	case strings.TrimSpace(cfg.Name) == "":
		return config{}, errors.New("name is required")
	case strings.TrimSpace(cfg.KeyFile) == "":
		return config{}, errors.New("key_file is required")
	case strings.TrimSpace(cfg.CoordinatorKey) == "":
		return config{}, errors.New("coordinator_key is required: without it " +
			"nothing can be verified and this prober would probe on anyone's say-so")
	case len(cfg.Checks) > 0 && strings.TrimSpace(cfg.CoordinatorURL) == "":
		return config{}, errors.New("coordinator_url is required when checks are assigned")
	}

	for _, c := range cfg.Checks {
		if err := c.toCheck().Validate(); err != nil {
			return config{}, err
		}
	}
	return cfg, nil
}
