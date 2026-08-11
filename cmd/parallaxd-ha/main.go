// Command parallaxd-ha performs guarded, explicitly authorized coordinator
// promotion. It cannot fence a host: the operator must positively fence and
// independently verify the old primary before supplying the confirmation.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kilo666mj/parallaxd/internal/haops"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "parallaxd-ha:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("parallaxd-ha", flag.ContinueOnError)
	url := fs.String("target", "", "standby coordinator base URL")
	tokenFile := fs.String("token-file", "", "operator token file")
	actor := fs.String("actor", "", "operator recorded with the promotion")
	maxSyncAge := fs.Duration("max-sync-age", 2*time.Minute, "maximum age of last successful replica sync")
	maxLag := fs.Duration("max-lag", 2*time.Minute, "maximum replicated state lag")
	allowQueue := fs.Bool("allow-queued-work", false, "allow nonempty result or notification queues")
	confirm := fs.Bool("confirm-primary-fenced", false, "attest that the old primary is positively fenced and independently verified")
	preflightOnly := fs.Bool("preflight-only", false, "validate the target without promoting it")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println("parallaxd-ha", version)
		return nil
	}
	if *url == "" {
		return errors.New("-target is required")
	}
	var token string
	if *tokenFile != "" {
		value, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("read token file: %w", err)
		}
		token = strings.TrimSpace(string(value))
	}
	client := haops.Client{BaseURL: *url, Token: token}
	d, err := client.Preflight(context.Background(), haops.PreflightOptions{
		MaxSyncAge: *maxSyncAge, MaxLag: *maxLag, AllowQueue: *allowQueue,
	})
	if err != nil {
		return fmt.Errorf("preflight failed: %w", err)
	}
	fmt.Printf("preflight passed: standby sync=%s lag=%dms queued_results=%d pending_notifications=%d\n",
		d.HA.LastReplicaSync.Format(time.RFC3339), d.HA.ReplicationLagMS,
		d.ResultQueue.Depth, d.Notifications.Pending)
	if *preflightOnly {
		return nil
	}
	if !*confirm {
		return errors.New("refusing promotion: fence the old primary, verify the service and network fences through an independent path, then pass -confirm-primary-fenced")
	}
	if strings.TrimSpace(*actor) == "" || token == "" {
		return errors.New("-actor and a nonempty -token-file are required for promotion")
	}
	status, err := client.Promote(context.Background(), *actor, true)
	if err != nil {
		return fmt.Errorf("promotion failed: %w", err)
	}
	fmt.Printf("promoted target: active=%t promoted=%t actor=%s\n", status.Active, status.Promoted, *actor)
	fmt.Println("NEXT: move probe traffic, verify reports and delivery, then rebuild the former primary as a standby; do not remove its fence first")
	return nil
}
