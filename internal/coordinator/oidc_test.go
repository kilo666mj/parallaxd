package coordinator

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// oidcLogin runs the browser OIDC flow against a fake provider that signs an
// ID token with idClaims, and returns where the browser ended up and who
// /v1/auth/me then reports.
func oidcLogin(t *testing.T, idClaims map[string]any) (*url.URL, oidcMe) {
	t.Helper()
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
			raw, signErr := jwt.Signed(signer).Claims(jwt.Claims{Issuer: provider.URL, Subject: "subject-1", Audience: jwt.Audience{"parallaxd-test"}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Hour))}).Claims(withNonce(idClaims, idNonce)).Serialize()
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
	_ = resp.Body.Close()
	final := resp.Request.URL
	resp, err = client.Get(coordinatorServer.URL + "/v1/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var me oidcMe
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	return final, me
}

type oidcMe struct {
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username"`
	Role          Role   `json:"role"`
}

func withNonce(claims map[string]any, nonce string) map[string]any {
	out := map[string]any{"nonce": nonce}
	for k, v := range claims {
		out[k] = v
	}
	return out
}

func TestOIDCLoginMapsVerifiedIdentityToLocalRole(t *testing.T) {
	final, me := oidcLogin(t, map[string]any{"email": "admin@example.com", "email_verified": true})
	if final.Path != "/" || final.RawQuery != "" {
		t.Fatalf("OIDC redirect ended at %s", final)
	}
	if !me.Authenticated || me.Username != "admin@example.com" || me.Role != RoleAdmin {
		t.Fatalf("OIDC principal=%+v", me)
	}
}

func TestOIDCLoginRejectsUnverifiedEmail(t *testing.T) {
	final, me := oidcLogin(t, map[string]any{"email": "admin@example.com", "email_verified": false})
	if me.Authenticated || final.Query().Get("error") == "" {
		t.Fatalf("unverified email signed in: ended at %s, principal=%+v", final, me)
	}
}

func TestOIDCLoginRejectsIdentityWithoutLocalAccount(t *testing.T) {
	final, me := oidcLogin(t, map[string]any{"email": "stranger@example.com", "email_verified": true})
	if me.Authenticated || final.Query().Get("error") == "" {
		t.Fatalf("unknown identity signed in: ended at %s, principal=%+v", final, me)
	}
}
