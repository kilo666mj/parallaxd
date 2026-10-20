package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.michaelspost.com/mcpkit/mcpkittest"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func connectHTTP(t *testing.T, handler http.Handler, token string) *mcp.ClientSession {
	t.Helper()
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, r)
		return recorder.Result(), nil
	})}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil).Connect(
		t.Context(), &mcp.StreamableClientTransport{Endpoint: "http://parallaxd.test/mcp", HTTPClient: client}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func connect(t *testing.T, server *mcp.Server) *mcp.ClientSession {
	t.Helper()
	return mcpkittest.Connect(t, server)
}

func TestServerPublishesExpectedToolsAndReadsStatus(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/status" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{"check": "website", "status": "up"}})
	}))
	defer api.Close()
	session := connect(t, New(Client{BaseURL: api.URL, Token: "secret"}, "test"))

	listed, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range listed.Tools {
		names = append(names, tool.Name)
	}
	for _, want := range []string{"parallaxd_get_status", "parallaxd_list_monitors", "parallaxd_get_monitor_options", "parallaxd_create_monitor", "parallaxd_delete_monitor", "parallaxd_rollback_monitors", "parallaxd_get_history", "parallaxd_list_maintenance", "parallaxd_create_maintenance", "parallaxd_update_maintenance", "parallaxd_delete_maintenance", "parallaxd_get_uptime", "parallaxd_list_notices", "parallaxd_create_notice", "parallaxd_post_notice_update", "parallaxd_edit_notice", "parallaxd_delete_notice"} {
		if !slices.Contains(names, want) {
			t.Errorf("missing tool %q in %v", want, names)
		}
	}
	var createTool *mcp.Tool
	for _, tool := range listed.Tools {
		if tool.Name == "parallaxd_create_monitor" {
			createTool = tool
		}
	}
	if createTool == nil {
		t.Fatal("create monitor tool missing")
	}
	schema, _ := json.Marshal(createTool.InputSchema)
	if !strings.Contains(string(schema), `"interval"`) || !strings.Contains(string(schema), `"distinct_providers"`) {
		t.Fatalf("create monitor schema is not typed: %s", schema)
	}
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "parallaxd_get_status"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result.StructuredContent)
	if string(encoded) != `{"data":[{"check":"website","status":"up"}]}` {
		t.Fatalf("structured result = %s", encoded)
	}
}

func TestRollbackUsesRevisionAPI(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/monitors/revisions/42/rollback" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["actor"] != "mcp-agent" {
			t.Fatalf("body = %#v", body)
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer api.Close()
	session := connect(t, New(Client{BaseURL: api.URL, Token: "secret", Actor: "mcp-agent"}, "test"))
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "parallaxd_rollback_monitors", Arguments: map[string]any{"revision_id": 42},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("tool returned error: %#v", result.Content)
	}
}

func TestCreateMonitorUsesCoordinatorManagementAPI(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/monitors" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		monitor := body["monitor"].(map[string]any)
		if body["actor"] != "mcp-agent" || monitor["name"] != "website" {
			t.Fatalf("body = %#v", body)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(monitor)
	}))
	defer api.Close()
	session := connect(t, New(Client{BaseURL: api.URL, Token: "secret", Actor: "mcp-agent"}, "test"))
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "parallaxd_create_monitor",
		Arguments: map[string]any{"monitor": map[string]any{
			"name": "website", "enabled": true, "kind": "http", "target": "https://example.com/health",
			"vantage": "public", "interval": "1m", "timeout": "10s",
			"quorum": map[string]any{"agree": 2, "of": 3, "distinct_providers": true},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("tool returned error: %#v", result.Content)
	}
}

func TestCoordinatorAuthorizationFailureReachesAgent(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "permission denied", http.StatusForbidden)
	}))
	defer api.Close()
	session := connect(t, New(Client{BaseURL: api.URL, Token: "viewer"}, "test"))
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "parallaxd_delete_monitor",
		Arguments: map[string]any{"name": "website"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("delete succeeded with a rejected token")
	}
}

func TestHostedForwardsRequestTokenAndEnforcesAPIAuthorization(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer viewer-secret" {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/status":
			_, _ = w.Write([]byte(`[{"check":"website","status":"up"}]`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/monitors/website":
			http.Error(w, "permission denied", http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	})
	handler, err := Hosted(api, "test")
	if err != nil {
		t.Fatal(err)
	}
	session := connectHTTP(t, handler, "viewer-secret")

	read, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "parallaxd_get_status"})
	if err != nil || read.IsError {
		t.Fatalf("viewer read: result=%#v err=%v", read, err)
	}
	write, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "parallaxd_delete_monitor", Arguments: map[string]any{"name": "website"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !write.IsError {
		t.Fatal("viewer mutation unexpectedly succeeded")
	}
}

func TestCreateMaintenanceUsesMaintenanceAPI(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/maintenance" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["actor"] != "mcp-agent" || body["every"] != "168h" || body["name"] != "patching" {
			t.Fatalf("body = %#v", body)
		}
		if _, ok := body["starts_at"]; ok {
			t.Fatalf("empty starts_at was sent: %#v", body)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"name":"patching"}`))
	}))
	defer api.Close()
	session := connect(t, New(Client{BaseURL: api.URL, Token: "secret", Actor: "mcp-agent"}, "test"))
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "parallaxd_create_maintenance", Arguments: map[string]any{"name": "patching", "ends_at": "2030-01-01T04:00:00Z", "every": "168h"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("tool returned error: %#v", result.Content)
	}
}

func TestNoticeToolsSendOnlyAPIFields(t *testing.T) {
	var seen []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if _, ok := body["id"]; ok {
			t.Fatalf("%s %s sent the id in the body: %#v", r.Method, r.URL.Path, body)
		}
		if body["actor"] != "mcp-agent" {
			t.Fatalf("%s %s actor=%v", r.Method, r.URL.Path, body["actor"])
		}
		seen = append(seen, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(`{"id":7}`))
	}))
	defer api.Close()
	session := connect(t, New(Client{BaseURL: api.URL, Token: "secret", Actor: "mcp-agent"}, "test"))
	for _, call := range []struct {
		name string
		args map[string]any
	}{
		{"parallaxd_create_notice", map[string]any{"kind": "incident", "title": "Slow logins", "message": "Looking into it.", "public": true}},
		{"parallaxd_post_notice_update", map[string]any{"id": 7, "state": "resolved", "message": "Fixed."}},
		{"parallaxd_edit_notice", map[string]any{"id": 7, "title": "Slow logins for some users"}},
		{"parallaxd_delete_notice", map[string]any{"id": 7, "note": "duplicate"}},
	} {
		result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: call.name, Arguments: call.args})
		if err != nil {
			t.Fatal(err)
		}
		if result.IsError {
			t.Fatalf("%s returned error: %#v", call.name, result.Content)
		}
	}
	want := []string{"POST /v1/notices", "POST /v1/notices/7/updates", "PUT /v1/notices/7", "DELETE /v1/notices/7"}
	if !slices.Equal(seen, want) {
		t.Fatalf("requests=%v, want %v", seen, want)
	}
}
