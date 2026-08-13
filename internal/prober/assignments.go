package prober

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

const defaultAssignmentInterval = 30 * time.Second

type AssignmentConfig struct {
	CoordinatorURL string
	Interval       time.Duration
	Client         *http.Client
}

// WatchAssignments reconciles the coordinator's assignment set with the
// locally running schedules. Removing a check cancels its loop; adding or
// changing one starts a fresh loop without restarting the prober.
func (p *Prober) WatchAssignments(ctx context.Context, cfg AssignmentConfig, out Submitter) {
	interval := cfg.Interval
	if interval <= 0 {
		interval = defaultAssignmentInterval
	}
	running := map[string]runningCheck{}
	reconcile := func() {
		checks, err := p.fetchAssignments(ctx, cfg)
		if err != nil {
			p.log.Warn("could not refresh assignments", "err", err)
			return
		}
		next := map[string]check.Check{}
		for _, chk := range checks {
			next[chk.Name] = chk
		}
		for name, active := range running {
			chk, keep := next[name]
			if keep && checksEqual(active.check, chk) {
				continue
			}
			active.cancel()
			delete(running, name)
		}
		for name, chk := range next {
			if _, exists := running[name]; exists {
				continue
			}
			runCtx, cancel := context.WithCancel(ctx)
			running[name] = runningCheck{check: chk, cancel: cancel}
			go func() {
				// A failover assignment exists because the previous owner is not
				// producing evidence. Probe immediately rather than adding a full
				// check interval to the monitoring gap.
				env, err := p.Run(runCtx, chk, "")
				if err == nil {
					err = out.Submit(runCtx, env)
				}
				if err != nil && runCtx.Err() == nil {
					p.log.Error("initial assigned probe failed", "check", chk.Name, "err", err)
				}
				p.runLoop(runCtx, chk, out)
			}()
		}
	}

	reconcile()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer func() {
		for _, active := range running {
			active.cancel()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcile()
		}
	}
}

type runningCheck struct {
	check  check.Check
	cancel context.CancelFunc
}

func checksEqual(a, b check.Check) bool {
	// JSON is the protocol representation and includes every behavior-affecting
	// field. Comparing it avoids a second hand-maintained field list here.
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(aa) == string(bb)
}

func (p *Prober) fetchAssignments(ctx context.Context, cfg AssignmentConfig) ([]check.Check, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(cfg.CoordinatorURL, "/")+"/v1/checks", nil)
	if err != nil {
		return nil, err
	}
	cred, err := p.credential()
	if err != nil {
		return nil, err
	}
	req.Header.Set(wire.ProberAuthHeader, cred)
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("coordinator returned %s", resp.Status)
	}
	var env wire.Envelope
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, maxRequestBytes)).Decode(&env); err != nil {
		return nil, err
	}
	raw, err := p.cfg.Keyring.OpenPublishedDocument(env, p.cfg.CoordinatorName, p.cfg.Name, "assignments", p.nowFunc())
	if err != nil {
		return nil, fmt.Errorf("verify assignments: %w", err)
	}
	var checks []check.Check
	if err := json.Unmarshal(raw, &checks); err != nil {
		return nil, fmt.Errorf("decode assignments: %w", err)
	}
	for _, chk := range checks {
		if err := chk.Validate(); err != nil {
			return nil, err
		}
	}
	return checks, nil
}
