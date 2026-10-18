package coordinator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

const testPassword = "correct horse battery staple"
const changedTestPassword = "correct horse battery staple again"

func authClient(t *testing.T, baseURL, username, password string) (*http.Client, Principal) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := client.Post(baseURL+"/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d", resp.StatusCode)
	}
	var principal Principal
	if err := json.NewDecoder(resp.Body).Decode(&principal); err != nil {
		t.Fatal(err)
	}
	if principal.CSRF == "" {
		t.Fatal("login did not return a CSRF token")
	}
	return client, principal
}

func authRequest(t *testing.T, client *http.Client, method, url, csrf string, body any) *http.Response {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		req.Header.Set("X-Parallaxd-CSRF", csrf)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestLocalUsersSessionsRolesAndTokens(t *testing.T) {
	cfg := durableConfig(t, "", &fakeNotifier{}, nil)
	cfg.BootstrapAdminUsername = "admin"
	cfg.BootstrapAdminPassword = testPassword
	cfg.InsecureSessionCookies = true
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	adminClient, admin := authClient(t, srv.URL, "admin", testPassword)
	if admin.Role != RoleAdmin || !roleAllows(admin.Role, PermissionManageAuth) {
		t.Fatalf("admin principal=%+v", admin)
	}
	resp := authRequest(t, adminClient, http.MethodPost, srv.URL+"/v1/auth/password", admin.CSRF, map[string]any{"current_password": testPassword, "new_password": changedTestPassword})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("change password status=%d", resp.StatusCode)
	}
	_, changed := authClient(t, srv.URL, "admin", changedTestPassword)
	if changed.Role != RoleAdmin {
		t.Fatalf("changed-password principal=%+v", changed)
	}

	// Cookie-authenticated mutations require the unguessable per-session CSRF
	// value returned by login.
	resp = authRequest(t, adminClient, http.MethodPost, srv.URL+"/v1/silences", "", map[string]any{"name": "deploy", "ends_at": time.Now().Add(time.Hour)})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mutation without CSRF status=%d", resp.StatusCode)
	}

	resp = authRequest(t, adminClient, http.MethodPost, srv.URL+"/v1/auth/users", admin.CSRF, map[string]any{"username": "reader", "password": testPassword, "role": RoleViewer})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create viewer status=%d", resp.StatusCode)
	}

	viewerClient, viewer := authClient(t, srv.URL, "reader", testPassword)
	resp = authRequest(t, viewerClient, http.MethodGet, srv.URL+"/v1/monitors", "", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer read status=%d", resp.StatusCode)
	}
	resp = authRequest(t, viewerClient, http.MethodPost, srv.URL+"/v1/silences", viewer.CSRF, map[string]any{"name": "forbidden", "ends_at": time.Now().Add(time.Hour)})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer mutation status=%d", resp.StatusCode)
	}

	resp = authRequest(t, adminClient, http.MethodPost, srv.URL+"/v1/auth/tokens", admin.CSRF, map[string]any{"name": "automation", "role": RoleOperator})
	if resp.StatusCode != http.StatusCreated {
		_ = resp.Body.Close()
		t.Fatalf("create token status=%d", resp.StatusCode)
	}
	var created struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if created.Secret == "" {
		t.Fatal("API token secret was not returned at creation")
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/silences", bytes.NewBufferString(`{"name":"automation","ends_at":"2030-01-02T03:04:05Z"}`))
	req.Header.Set("Authorization", "Bearer "+created.Secret)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("operator token mutation status=%d", resp.StatusCode)
	}
	if got := c.Silences()[0].CreatedBy; got != "token:automation" {
		t.Fatalf("token mutation actor=%q", got)
	}

	resp = authRequest(t, adminClient, http.MethodDelete, srv.URL+"/v1/auth/users/admin", admin.CSRF, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("delete last admin status=%d", resp.StatusCode)
	}
}

func TestMCPRouteRequiresAuthentication(t *testing.T) {
	cfg := durableConfig(t, "", &fakeNotifier{}, nil)
	cfg.OperatorToken = "secret"
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	c.SetMCPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	unauthorized := httptest.NewRecorder()
	c.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if unauthorized.Code != http.StatusUnauthorized || called {
		t.Fatalf("unauthorized MCP status=%d called=%t", unauthorized.Code, called)
	}

	authorized := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer secret")
	c.Handler().ServeHTTP(authorized, request)
	if authorized.Code != http.StatusNoContent || !called {
		t.Fatalf("authorized MCP status=%d called=%t", authorized.Code, called)
	}
}

func TestUsersAndSessionsRestoreWithoutPlaintextSecrets(t *testing.T) {
	stateFile := t.TempDir() + "/state.json"
	cfg := durableConfig(t, stateFile, &fakeNotifier{}, nil)
	cfg.BootstrapAdminUsername = "admin"
	cfg.BootstrapAdminPassword = testPassword
	cfg.InsecureSessionCookies = true
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.Handler())
	client, principal := authClient(t, srv.URL, "admin", testPassword)
	resp := authRequest(t, client, http.MethodPost, srv.URL+"/v1/auth/users", principal.CSRF, map[string]any{"username": "operator", "password": testPassword, "role": RoleOperator})
	_ = resp.Body.Close()
	srv.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create operator status=%d", resp.StatusCode)
	}

	restored, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	restoredServer := httptest.NewServer(restored.Handler())
	defer restoredServer.Close()
	_, got := authClient(t, restoredServer.URL, "operator", testPassword)
	if got.Role != RoleOperator {
		t.Fatalf("restored role=%q", got.Role)
	}

	var state persistedState
	raw, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(testPassword)) {
		t.Fatal("state file contains plaintext password")
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	if state.Version != 6 || len(state.Users) != 2 || len(state.Sessions) == 0 {
		t.Fatalf("persisted identity state=%+v", state)
	}
}
