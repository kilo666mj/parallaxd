package coordinator

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"go.michaelspost.com/oidcrp"
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

// newOIDC builds the shared relying-party flow. oidcrp owns discovery, PKCE,
// state and nonce cookies, and ID-token verification; the coordinator keeps
// account mapping, sessions, standby refusal, and rate limiting.
func (c *Coordinator) newOIDC() *oidcrp.Service {
	cfg := c.cfg.OIDC
	return oidcrp.New(oidcrp.Config{
		Issuer:          cfg.Issuer,
		ClientID:        cfg.ClientID,
		ClientSecret:    cfg.ClientSecret,
		RedirectURL:     cfg.RedirectURL,
		StateCookieName: "parallaxd_oidc",
		LoginPath:       "/",
		LoginStartPath:  "/v1/auth/oidc/start",
		CallbackPath:    "/v1/auth/oidc/callback",
		SuccessPath:     "/",
		HTTPClient:      c.client,
		Logger:          slog.NewLogLogger(c.log.Handler(), slog.LevelWarn),
	}, oidcSessions{c})
}

// oidcSessions maps verified identities to existing local accounts. OIDC never
// provisions users: an operator must create the account and assign its role.
type oidcSessions struct{ c *Coordinator }

func (s oidcSessions) Valid(r *http.Request) bool {
	principal, ok := s.c.authenticate(r)
	return ok && principal.Method == "session"
}

func (s oidcSessions) Issue(w http.ResponseWriter, _ *http.Request, identity oidcrp.Identity) error {
	c := s.c
	claim := c.cfg.OIDC.UsernameClaim
	if claim == "" {
		claim = "email"
	}
	username, _ := identity.Claims[claim].(string)
	username = strings.TrimSpace(username)
	if claim == "email" && !c.cfg.OIDC.AllowUnverifiedEmail && !identity.EmailVerified {
		c.log.Warn("OIDC email identity is not verified", "username", username)
		return errors.New("OIDC email identity is not verified")
	}
	c.authMu.Lock()
	user, exists := c.users[username]
	c.authMu.Unlock()
	if username == "" || !exists || user.Disabled {
		c.log.Warn("OIDC user has no active local account", "claim", claim, "username", username)
		return fmt.Errorf("no active parallaxd account for %s %q", claim, username)
	}
	_, err := c.createSession(w, user)
	return err
}

// Logout stays on /v1/auth/logout, which also requires CSRF.
func (oidcSessions) Clear(http.ResponseWriter, *http.Request) {}

func (c *Coordinator) oidcAllowed(w http.ResponseWriter, r *http.Request) bool {
	if !c.oidcEnabled() {
		http.NotFound(w, r)
		return false
	}
	if c.isStandby() {
		http.Error(w, "sign in through the active coordinator", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func (c *Coordinator) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if !c.oidcAllowed(w, r) {
		return
	}
	limitKey := "oidc:" + remoteHost(r.RemoteAddr)
	if c.loginLimited(limitKey) {
		http.Error(w, "too many sign-in attempts", http.StatusTooManyRequests)
		return
	}
	c.recordLoginFailure(limitKey)
	c.oidc.LoginStart(w, r)
}

func (c *Coordinator) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !c.oidcAllowed(w, r) {
		return
	}
	c.oidc.Callback(w, r)
}
