package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientSendsAuthenticationAndActor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("X-Parallaxd-Actor"); got != "agent" {
			t.Errorf("X-Parallaxd-Actor = %q", got)
		}
		if r.Method != http.MethodGet || r.URL.Path != "/v1/status" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"check":"website","status":"up"}]`))
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, Token: "secret", Actor: "agent"}
	var out []map[string]any
	if err := client.Get(context.Background(), "/v1/status", &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0]["status"] != "up" {
		t.Fatalf("response = %#v", out)
	}
}

func TestClientReturnsBoundedCoordinatorError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, strings.Repeat("denied", 1000), http.StatusForbidden)
	}))
	defer server.Close()
	client := Client{BaseURL: server.URL, Token: "secret"}
	var out any
	err := client.Get(context.Background(), "/v1/status", &out)
	if err == nil || !strings.Contains(err.Error(), "403 Forbidden") || len(err.Error()) > 4200 {
		t.Fatalf("error = %v", err)
	}
}

func TestClientValidate(t *testing.T) {
	for _, test := range []struct {
		client Client
		ok     bool
	}{
		{Client{BaseURL: "https://status.example", Token: "secret"}, true},
		{Client{BaseURL: "status.example", Token: "secret"}, false},
		{Client{BaseURL: "file:///tmp/socket", Token: "secret"}, false},
		{Client{BaseURL: "https://status.example"}, false},
	} {
		if got := test.client.Validate() == nil; got != test.ok {
			t.Errorf("Validate(%#v) success = %t, want %t", test.client, got, test.ok)
		}
	}
}
