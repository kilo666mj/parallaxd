// Command parallaxd-watch is the far end of the dead-man's switch.
//
// It receives the coordinator's heartbeat and alerts when it stops. That is
// all it does, and the smallness is the point: this is the component that has
// to keep working when everything it watches has stopped.
//
// **Run it on a different provider from the coordinator.** Not a different
// company — a different failure domain. On the same host it dies with what it
// is watching, which is the one thing it must not do.
//
// The watch is mutual without needing a second channel: this alerts when the
// coordinator stops checking in, and the coordinator alerts when it can no
// longer deliver here. Either dying alone is reported by the other.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kilo666mj/parallaxd/internal/coordinator"
	"github.com/kilo666mj/parallaxd/internal/watch"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

var version = "dev"

type config struct {
	// Name identifies this watcher in its alerts and in the heartbeat it
	// sends back to the coordinator.
	Name string `json:"name"`

	Listen string `json:"listen"`

	// Grace is how long the coordinator may go quiet before it is declared
	// dead. A small multiple of its heartbeat interval: too tight and one
	// lost packet pages someone, too loose and a dead coordinator goes
	// unnoticed for longer than an outage lasts.
	Grace duration `json:"grace"`

	// CheckInterval is how often the grace period is evaluated.
	CheckInterval duration `json:"check_interval,omitempty"`

	// Webhook receives the alert. Deliberately separate from the
	// coordinator's: a watcher that alerted through the thing it watches
	// would be silent in exactly the case it exists for.
	Webhook        string            `json:"webhook,omitempty"`
	WebhookHeaders map[string]string `json:"webhook_headers,omitempty"`

	CoordinatorName string `json:"coordinator_name"`
	CoordinatorKey  string `json:"coordinator_key"`
}

// There is deliberately no heartbeat back to the coordinator. The coordinator
// already learns this watcher has died by failing to deliver to it — see
// KindUnwatched — and a second mechanism reporting the same fact would be two
// things to keep correct for one signal.

type duration time.Duration

func (d *duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf(`duration must be a string like "5m": %w`, err)
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
		configPath = flag.String("config", "/etc/parallaxd/watch.json", "config file path")
		debug      = flag.Bool("debug", false, "verbose logging")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("parallaxd-watch", version)
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

func run(configPath string, log *slog.Logger) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	var notifier coordinator.Notifier = coordinator.LogNotifier{Logger: log}
	if cfg.Webhook != "" {
		notifier = coordinator.Notifiers{
			coordinator.LogNotifier{Logger: log},
			coordinator.WebhookNotifier{URL: cfg.Webhook, Headers: cfg.WebhookHeaders},
		}
	} else {
		// Said out loud. A watcher whose only output is a log on a host nobody
		// reads is not a dead-man's switch, it is a diary.
		log.Warn("no webhook configured; a dead coordinator will be recorded " +
			"in this journal and nowhere else")
	}

	w := watch.New(time.Duration(cfg.Grace), time.Now)
	pub, err := wire.DecodePublicKey(cfg.CoordinatorKey)
	if err != nil {
		return fmt.Errorf("coordinator key: %w", err)
	}
	ring := wire.NewKeyring()
	if err := ring.Add(cfg.CoordinatorName, pub); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/heartbeat", func(rw http.ResponseWriter, r *http.Request) {
		var env wire.Envelope
		if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 128<<10)).Decode(&env); err != nil {
			http.Error(rw, "malformed heartbeat", http.StatusBadRequest)
			return
		}
		b, err := ring.OpenHeartbeat(env, time.Now(), time.Duration(cfg.Grace))
		if err != nil {
			log.Warn("refused heartbeat", "peer", env.Peer, "err", err)
			http.Error(rw, "heartbeat rejected", http.StatusForbidden)
			return
		}
		if recovered := w.Record(b); recovered {
			alert(ctx, notifier, log, coordinator.KindWatchRecovered, w.State().Summary())
		}
		rw.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("GET /v1/status", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(w.State())
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	errs := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen, "watcher", cfg.Name,
			"grace", time.Duration(cfg.Grace), "version", version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	go watchLoop(ctx, w, notifier, log, time.Duration(cfg.CheckInterval))

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

func watchLoop(ctx context.Context, w *watch.Watcher, n coordinator.Notifier,
	log *slog.Logger, interval time.Duration,
) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if w.Check() {
				alert(ctx, n, log, coordinator.KindWatchLost, w.State().Summary())
			}
		}
	}
}

func alert(ctx context.Context, n coordinator.Notifier, log *slog.Logger,
	kind coordinator.Kind, detail string,
) {
	a := coordinator.Alert{Kind: kind, Detail: detail, At: time.Now().UTC()}
	if err := n.Notify(ctx, a); err != nil {
		log.Error("could not deliver alert", "kind", string(kind), "err", err)
	}
}

func loadConfig(path string) (config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return config{}, fmt.Errorf("read config: %w", err)
	}
	cfg := config{Listen: "0.0.0.0:8974", Name: "watch", Grace: duration(5 * time.Minute), CoordinatorName: "coordinator"}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return config{}, fmt.Errorf("parse config: %w", err)
	}
	if time.Duration(cfg.Grace) <= 0 {
		return config{}, errors.New("grace must be positive")
	}
	if cfg.CoordinatorName == "" || cfg.CoordinatorKey == "" {
		return config{}, errors.New("coordinator_name and coordinator_key are required")
	}
	return cfg, nil
}
