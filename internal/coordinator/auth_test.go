package coordinator

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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
	defer resp.Body.Close()
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

func TestOIDCLoginMapsVerifiedIdentityToLocalRole(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: "test-key", Algorithm: string(jose.RS256), Use: "sig"}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: privateKey, KeyID: "test-key"}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	var nonce string
	var nonceMu sync.Mutex
	provider := httptest.NewUnstartedServer(nil)
	provider.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(w, map[string]any{"issuer": provider.URL, "authorization_endpoint": provider.URL + "/authorize", "token_endpoint": provider.URL + "/token", "jwks_uri": provider.URL + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/authorize":
			nonceMu.Lock()
			nonce = r.URL.Query().Get("nonce")
			nonceMu.Unlock()
			redirect, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
			query := redirect.Query()
			query.Set("state", r.URL.Query().Get("state"))
			query.Set("code", "test-code")
			redirect.RawQuery = query.Encode()
			http.Redirect(w, r, redirect.String(), http.StatusFound)
		case "/token":
			nonceMu.Lock()
			idNonce := nonce
			nonceMu.Unlock()
			now := time.Now()
			raw, signErr := jwt.Signed(signer).Claims(jwt.Claims{Issuer: provider.URL, Subject: "subject-1", Audience: jwt.Audience{"parallaxd-test"}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Hour))}).Claims(map[string]any{"nonce": idNonce, "email": "admin@example.com", "email_verified": true}).Serialize()
			if signErr != nil {
				http.Error(w, "sign", http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
		case "/keys":
			writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicKey}})
		default:
			http.NotFound(w, r)
		}
	})
	provider.Start()
	defer provider.Close()

	coordinatorServer := httptest.NewUnstartedServer(nil)
	coordinatorURL := "http://" + coordinatorServer.Listener.Addr().String()
	cfg := durableConfig(t, "", &fakeNotifier{}, nil)
	cfg.BootstrapAdminUsername = "admin@example.com"
	cfg.BootstrapAdminPassword = testPassword
	cfg.InsecureSessionCookies = true
	cfg.OIDC = OIDCConfig{Issuer: provider.URL, ClientID: "parallaxd-test", RedirectURL: coordinatorURL + "/v1/auth/oidc/callback", UsernameClaim: "email", AllowInsecureIssuer: true}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	coordinatorServer.Config.Handler = c.Handler()
	coordinatorServer.Start()
	defer coordinatorServer.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Get(coordinatorServer.URL + "/v1/auth/oidc/start")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/" {
		t.Fatalf("OIDC redirect ended at %s with status %d", resp.Request.URL, resp.StatusCode)
	}
	resp, err = client.Get(coordinatorServer.URL + "/v1/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var me struct {
		Authenticated bool   `json:"authenticated"`
		Username      string `json:"username"`
		Role          Role   `json:"role"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	if !me.Authenticated || me.Username != "admin@example.com" || me.Role != RoleAdmin {
		t.Fatalf("OIDC principal=%+v", me)
	}
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
	resp.Body.Close()
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
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mutation without CSRF status=%d", resp.StatusCode)
	}

	resp = authRequest(t, adminClient, http.MethodPost, srv.URL+"/v1/auth/users", admin.CSRF, map[string]any{"username": "reader", "password": testPassword, "role": RoleViewer})
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create viewer status=%d", resp.StatusCode)
	}

	viewerClient, viewer := authClient(t, srv.URL, "reader", testPassword)
	resp = authRequest(t, viewerClient, http.MethodGet, srv.URL+"/v1/monitors", "", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer read status=%d", resp.StatusCode)
	}
	resp = authRequest(t, viewerClient, http.MethodPost, srv.URL+"/v1/silences", viewer.CSRF, map[string]any{"name": "forbidden", "ends_at": time.Now().Add(time.Hour)})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer mutation status=%d", resp.StatusCode)
	}

	resp = authRequest(t, adminClient, http.MethodPost, srv.URL+"/v1/auth/tokens", admin.CSRF, map[string]any{"name": "automation", "role": RoleOperator})
	if resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		t.Fatalf("create token status=%d", resp.StatusCode)
	}
	var created struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if created.Secret == "" {
		t.Fatal("API token secret was not returned at creation")
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/silences", bytes.NewBufferString(`{"name":"automation","ends_at":"2030-01-02T03:04:05Z"}`))
	req.Header.Set("Authorization", "Bearer "+created.Secret)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("operator token mutation status=%d", resp.StatusCode)
	}
	if got := c.Silences()[0].CreatedBy; got != "token:automation" {
		t.Fatalf("token mutation actor=%q", got)
	}

	resp = authRequest(t, adminClient, http.MethodDelete, srv.URL+"/v1/auth/users/admin", admin.CSRF, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("delete last admin status=%d", resp.StatusCode)
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
	resp.Body.Close()
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
