// Package haops contains the deliberately small operator-side portion of a
// coordinator failover. It validates the recovery point and performs the
// authenticated promotion; fencing and traffic movement remain explicit
// infrastructure operations because reachability is not proof of fencing.
package haops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxResponse = 4 << 20

type Status struct {
	Role                 string    `json:"role"`
	Active               bool      `json:"active"`
	Promoted             bool      `json:"promoted"`
	LastReplicaSync      time.Time `json:"last_replica_sync"`
	ReplicationLagMS     int64     `json:"replication_lag_ms"`
	LastReplicationError string    `json:"last_replication_error"`
}

type Diagnostics struct {
	ResultQueue struct {
		Depth int `json:"depth"`
	} `json:"result_queue"`
	Notifications struct {
		Pending int `json:"pending"`
	} `json:"notifications"`
	HA Status `json:"ha"`
}

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	Now     func() time.Time
}

type PreflightOptions struct {
	MaxSyncAge time.Duration
	MaxLag     time.Duration
	AllowQueue bool
}

func (c Client) Preflight(ctx context.Context, opts PreflightOptions) (Diagnostics, error) {
	var d Diagnostics
	if err := c.getJSON(ctx, "/v1/diagnostics", &d); err != nil {
		return d, err
	}
	if d.HA.Role != "standby" {
		return d, fmt.Errorf("target role is %q, want standby", d.HA.Role)
	}
	if d.HA.Active || d.HA.Promoted {
		return d, errors.New("target is already active or promoted")
	}
	if d.HA.LastReplicationError != "" {
		return d, fmt.Errorf("replication error: %s", d.HA.LastReplicationError)
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	if d.HA.LastReplicaSync.IsZero() {
		return d, errors.New("target has never completed replication")
	}
	if opts.MaxSyncAge > 0 && now().Sub(d.HA.LastReplicaSync) > opts.MaxSyncAge {
		return d, fmt.Errorf("last replica sync is older than %s", opts.MaxSyncAge)
	}
	if opts.MaxLag > 0 && time.Duration(d.HA.ReplicationLagMS)*time.Millisecond > opts.MaxLag {
		return d, fmt.Errorf("replication lag exceeds %s", opts.MaxLag)
	}
	if !opts.AllowQueue && (d.ResultQueue.Depth != 0 || d.Notifications.Pending != 0) {
		return d, fmt.Errorf("target has queued work: results=%d notifications=%d",
			d.ResultQueue.Depth, d.Notifications.Pending)
	}
	return d, nil
}

func (c Client) Promote(ctx context.Context, actor string, primaryFenced bool) (Status, error) {
	var status Status
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return status, errors.New("actor is required")
	}
	if !primaryFenced {
		return status, errors.New("positive primary fencing confirmation is required")
	}
	body, err := json.Marshal(map[string]any{"actor": actor, "confirm_primary_fenced": true})
	if err != nil {
		return status, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.BaseURL, "/")+"/v1/ha/promote", bytes.NewReader(body))
	if err != nil {
		return status, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if err := c.doJSON(req, &status); err != nil {
		return status, err
	}
	if !status.Active || !status.Promoted {
		return status, errors.New("promotion response did not report an active promoted coordinator")
	}
	return status, nil
}

func (c Client) getJSON(ctx context.Context, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+path, nil)
	if err != nil {
		return err
	}
	return c.doJSON(req, dst)
}

func (c Client) doJSON(req *http.Request, dst any) error {
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("coordinator returned %s: %s", resp.Status, strings.TrimSpace(string(message)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(dst); err != nil {
		return fmt.Errorf("decode coordinator response: %w", err)
	}
	return nil
}
