package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/kilo666mj/mcpkit/mcpkittest"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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
	for _, want := range []string{"parallaxd_get_status", "parallaxd_list_monitors", "parallaxd_get_monitor_options", "parallaxd_create_monitor", "parallaxd_delete_monitor", "parallaxd_rollback_monitors", "parallaxd_get_history"} {
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
