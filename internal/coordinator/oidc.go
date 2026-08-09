package coordinator

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	Issuer               string
	ClientID             string
	ClientSecret         string
	RedirectURL          string
	UsernameClaim        string
	Label                string
	AllowInsecureIssuer  bool
	AllowUnverifiedEmail bool
}

type oidcAttempt struct {
	Nonce        string
	CodeVerifier string
	ExpiresAt    time.Time
}

type oidcRuntime struct {
	mu       sync.Mutex
	provider *oidc.Provider
	attempts map[string]oidcAttempt
}

func validateOIDCConfig(cfg OIDCConfig) error {
	if cfg.Issuer == "" && cfg.ClientID == "" && cfg.RedirectURL == "" && cfg.ClientSecret == "" {
		return nil
	}
	if strings.TrimSpace(cfg.Issuer) == "" || strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(cfg.RedirectURL) == "" {
		return errors.New("OIDC issuer, client_id, and redirect_url are required together")
	}
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Host == "" || (issuer.Scheme != "https" && !cfg.AllowInsecureIssuer) {
		return errors.New("OIDC issuer must be an absolute HTTPS URL")
	}
	redirect, err := url.Parse(cfg.RedirectURL)
	if err != nil || redirect.Host == "" || (redirect.Scheme != "https" && !cfg.AllowInsecureIssuer) {
		return errors.New("OIDC redirect_url must be an absolute HTTPS URL")
	}
	return nil
}

func (c *Coordinator) oidcEnabled() bool { return c.cfg.OIDC.Issuer != "" }

func (c *Coordinator) oidcProvider(ctx context.Context) (*oidc.Provider, error) {
	c.oidc.mu.Lock()
	defer c.oidc.mu.Unlock()
	if c.oidc.provider != nil {
		return c.oidc.provider, nil
	}
	discoveryContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	discoveryContext = oidc.ClientContext(discoveryContext, c.client)
	provider, err := oidc.NewProvider(discoveryContext, c.cfg.OIDC.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	c.oidc.provider = provider
	return provider, nil
}

func (c *Coordinator) oauthConfig(provider *oidc.Provider) oauth2.Config {
	return oauth2.Config{ClientID: c.cfg.OIDC.ClientID, ClientSecret: c.cfg.OIDC.ClientSecret,
		Endpoint: provider.Endpoint(), RedirectURL: c.cfg.OIDC.RedirectURL,
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
}

func (c *Coordinator) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if !c.oidcEnabled() {
		http.NotFound(w, r)
		return
	}
	if c.isStandby() {
		http.Error(w, "sign in through the active coordinator", http.StatusServiceUnavailable)
		return
	}
	provider, err := c.oidcProvider(r.Context())
	if err != nil {
		c.log.Error("OIDC discovery failed", "err", err)
		http.Error(w, "identity provider unavailable", http.StatusBadGateway)
		return
	}
	state, err := randomSecret(32)
	if err != nil {
		http.Error(w, "could not begin sign in", http.StatusInternalServerError)
		return
	}
	nonce, err := randomSecret(24)
	if err != nil {
		http.Error(w, "could not begin sign in", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	now := c.now()
	c.oidc.mu.Lock()
	for hash, attempt := range c.oidc.attempts {
		if !now.Before(attempt.ExpiresAt) {
			delete(c.oidc.attempts, hash)
		}
	}
	if len(c.oidc.attempts) >= 1024 {
		c.oidc.mu.Unlock()
		http.Error(w, "too many sign-in attempts", http.StatusTooManyRequests)
		return
	}
	c.oidc.attempts[secretHash(state)] = oidcAttempt{Nonce: nonce, CodeVerifier: verifier, ExpiresAt: now.Add(10 * time.Minute)}
	c.oidc.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "parallaxd_oidc_state", Value: state, Path: "/v1/auth/oidc/callback", HttpOnly: true, Secure: !c.cfg.InsecureSessionCookies, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	oauthConfig := c.oauthConfig(provider)
	location := oauthConfig.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, location, http.StatusFound)
}

func (c *Coordinator) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !c.oidcEnabled() {
		http.NotFound(w, r)
		return
	}
	if c.isStandby() {
		http.Error(w, "sign in through the active coordinator", http.StatusServiceUnavailable)
		return
	}
	cookie, err := r.Cookie("parallaxd_oidc_state")
	state := r.URL.Query().Get("state")
	if err != nil || state == "" || len(cookie.Value) != len(state) || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		http.Error(w, "invalid OIDC state", http.StatusBadRequest)
		return
	}
	c.oidc.mu.Lock()
	attempt, ok := c.oidc.attempts[secretHash(state)]
	delete(c.oidc.attempts, secretHash(state))
	c.oidc.mu.Unlock()
	if !ok || !c.now().Before(attempt.ExpiresAt) {
		http.Error(w, "OIDC sign-in attempt expired", http.StatusBadRequest)
		return
	}
	if providerError := r.URL.Query().Get("error"); providerError != "" {
		http.Error(w, "identity provider rejected sign in", http.StatusUnauthorized)
		return
	}
	provider, err := c.oidcProvider(r.Context())
	if err != nil {
		http.Error(w, "identity provider unavailable", http.StatusBadGateway)
		return
	}
	oauthConfig := c.oauthConfig(provider)
	oidcContext := oidc.ClientContext(r.Context(), c.client)
	token, err := oauthConfig.Exchange(oidcContext, r.URL.Query().Get("code"), oauth2.VerifierOption(attempt.CodeVerifier))
	if err != nil {
		c.log.Warn("OIDC code exchange failed", "err", err)
		http.Error(w, "OIDC sign in failed", http.StatusUnauthorized)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "identity provider omitted ID token", http.StatusUnauthorized)
		return
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: c.cfg.OIDC.ClientID}).Verify(oidcContext, rawIDToken)
	if err != nil {
		c.log.Warn("OIDC ID token verification failed", "err", err)
		http.Error(w, "OIDC identity could not be verified", http.StatusUnauthorized)
		return
	}
	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "OIDC claims could not be read", http.StatusUnauthorized)
		return
	}
	if nonce, _ := claims["nonce"].(string); len(nonce) != len(attempt.Nonce) || subtle.ConstantTimeCompare([]byte(nonce), []byte(attempt.Nonce)) != 1 {
		http.Error(w, "OIDC nonce mismatch", http.StatusUnauthorized)
		return
	}
	claim := c.cfg.OIDC.UsernameClaim
	if claim == "" {
		claim = "email"
	}
	username, _ := claims[claim].(string)
	username = strings.TrimSpace(username)
	if claim == "email" && !c.cfg.OIDC.AllowUnverifiedEmail {
		verified, _ := claims["email_verified"].(bool)
		if !verified {
			http.Error(w, "OIDC email identity is not verified", http.StatusForbidden)
			return
		}
	}
	c.authMu.Lock()
	user, exists := c.users[username]
	c.authMu.Unlock()
	if !exists || user.Disabled {
		c.log.Warn("OIDC user has no active local account", "claim", claim, "username", username)
		http.Error(w, "no active parallaxd account matches this identity", http.StatusForbidden)
		return
	}
	if _, err := c.createSession(w, user); err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "parallaxd_oidc_state", Path: "/v1/auth/oidc/callback", MaxAge: -1, HttpOnly: true, Secure: !c.cfg.InsecureSessionCookies, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusFound)
}
