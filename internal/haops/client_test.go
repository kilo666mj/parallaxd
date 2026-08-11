package haops

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPreflightAndPromote(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	promoted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/diagnostics":
			fmt.Fprintf(w, `{"result_queue":{"depth":0},"notifications":{"pending":0},"ha":{"role":"standby","active":false,"promoted":false,"last_replica_sync":%q,"replication_lag_ms":250}}`, now.Add(-time.Second).Format(time.RFC3339))
		case "/v1/ha/promote":
			if r.Header.Get("Authorization") != "Bearer secret" {
				http.Error(w, "bad token", http.StatusUnauthorized)
				return
			}
			promoted = true
			fmt.Fprint(w, `{"role":"standby","active":true,"promoted":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := Client{BaseURL: srv.URL, Token: "secret", Now: func() time.Time { return now }}
	if _, err := c.Preflight(context.Background(), PreflightOptions{MaxSyncAge: time.Minute, MaxLag: time.Second}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Promote(context.Background(), "operator", true); err != nil {
		t.Fatal(err)
	}
	if !promoted {
		t.Fatal("promotion endpoint was not called")
	}
}

func TestPreflightRefusesUnsafeTargets(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		ha   string
	}{
		{"primary", `"role":"primary","last_replica_sync":"2026-08-11T12:00:00Z"`},
		{"active", `"role":"standby","active":true,"last_replica_sync":"2026-08-11T12:00:00Z"`},
		{"never synced", `"role":"standby"`},
		{"stale", `"role":"standby","last_replica_sync":"2026-08-11T11:00:00Z"`},
		{"replication error", `"role":"standby","last_replica_sync":"2026-08-11T12:00:00Z","last_replication_error":"boom"`},
		{"lag", `"role":"standby","last_replica_sync":"2026-08-11T12:00:00Z","replication_lag_ms":60000`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintf(w, `{"result_queue":{"depth":0},"notifications":{"pending":0},"ha":{%s}}`, tt.ha)
			}))
			defer srv.Close()
			c := Client{BaseURL: srv.URL, Now: func() time.Time { return now }}
			if _, err := c.Preflight(context.Background(), PreflightOptions{MaxSyncAge: time.Minute, MaxLag: time.Second}); err == nil {
				t.Fatal("unsafe preflight passed")
			}
		})
	}
}

func TestPreflightRefusesQueuedWorkByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"result_queue":{"depth":1},"notifications":{"pending":2},"ha":{"role":"standby","last_replica_sync":"2026-08-11T12:00:00Z"}}`)
	}))
	defer srv.Close()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	c := Client{BaseURL: srv.URL, Now: func() time.Time { return now }}
	if _, err := c.Preflight(context.Background(), PreflightOptions{MaxSyncAge: time.Minute}); err == nil {
		t.Fatal("queued work was accepted")
	}
	if _, err := c.Preflight(context.Background(), PreflightOptions{MaxSyncAge: time.Minute, AllowQueue: true}); err != nil {
		t.Fatal(err)
	}
}

func TestPromoteRequiresExplicitFence(t *testing.T) {
	c := Client{}
	if _, err := c.Promote(context.Background(), "operator", false); err == nil {
		t.Fatal("promotion without fence confirmation succeeded")
	}
}
