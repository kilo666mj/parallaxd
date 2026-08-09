package coordinator

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

type Permission string

const (
	PermissionView       Permission = "fleet:view"
	PermissionOperate    Permission = "fleet:operate"
	PermissionRollback   Permission = "catalog:rollback"
	PermissionManageAuth Permission = "auth:manage"
)

type User struct {
	Username     string    `json:"username"`
	Role         Role      `json:"role"`
	PasswordHash string    `json:"-"`
	LocalLogin   bool      `json:"local_login"`
	Disabled     bool      `json:"disabled,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type persistedUser struct {
	Username     string    `json:"username"`
	Role         Role      `json:"role"`
	PasswordHash string    `json:"password_hash"`
	Disabled     bool      `json:"disabled,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type APIToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Role       Role       `json:"role"`
	Prefix     string     `json:"prefix"`
	TokenHash  string     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type persistedAPIToken struct {
	APIToken
	TokenHash string `json:"token_hash"`
}

type Session struct {
	TokenHash string    `json:"token_hash"`
	CSRFHash  string    `json:"csrf_hash"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Principal struct {
	Actor       string       `json:"username"`
	Role        Role         `json:"role"`
	Permissions []Permission `json:"permissions"`
	Method      string       `json:"-"`
	CSRF        string       `json:"csrf_token,omitempty"`
}

func validRole(role Role) bool {
	return role == RoleViewer || role == RoleOperator || role == RoleAdmin
}

func permissionsFor(role Role) []Permission {
	switch role {
	case RoleAdmin:
		return []Permission{PermissionView, PermissionOperate, PermissionRollback, PermissionManageAuth}
	case RoleOperator:
		return []Permission{PermissionView, PermissionOperate}
	case RoleViewer:
		return []Permission{PermissionView}
	default:
		return nil
	}
}

func roleAllows(role Role, permission Permission) bool {
	for _, allowed := range permissionsFor(role) {
		if allowed == permission {
			return true
		}
	}
	return false
}

func validUsername(username string) bool {
	if len(username) < 1 || len(username) > 64 {
		return false
	}
	for _, r := range username {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._-@", r) {
			continue
		}
		return false
	}
	return true
}

func randomSecret(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func secretHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func hashPassword(password string) (string, error) {
	if len(password) < 12 || len(password) > 1024 {
		return "", errors.New("password must be between 12 and 1024 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	const memory = 64 * 1024
	const iterations = 1
	const parallelism = 2
	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	var memory, iterations uint64
	var parallelism uint64
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	// Reject non-canonical parameter text instead of accepting trailing junk.
	if parts[3] != "m="+strconv.FormatUint(memory, 10)+",t="+strconv.FormatUint(iterations, 10)+",p="+strconv.FormatUint(parallelism, 10) {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) != 32 || memory < 8*1024 || memory > 256*1024 || iterations < 1 || iterations > 10 || parallelism < 1 || parallelism > 16 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(memory), uint8(parallelism), uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func (c *Coordinator) authEnabled() bool {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	return c.cfg.OperatorToken != "" || len(c.users) > 0 || len(c.apiTokens) > 0
}

func (c *Coordinator) ensureBootstrapAdmin() error {
	username := strings.TrimSpace(c.cfg.BootstrapAdminUsername)
	password := c.cfg.BootstrapAdminPassword
	if username == "" && password == "" {
		return nil
	}
	if !validUsername(username) {
		return errors.New("bootstrap administrator username is invalid")
	}
	c.authMu.Lock()
	if len(c.users) > 0 {
		c.authMu.Unlock()
		return nil
	}
	c.authMu.Unlock()
	hash, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("bootstrap administrator password: %w", err)
	}
	now := c.now().UTC()
	c.authMu.Lock()
	c.users[username] = User{Username: username, Role: RoleAdmin, PasswordHash: hash, CreatedAt: now, UpdatedAt: now}
	c.authMu.Unlock()
	if !c.cfg.SkipRestore {
		if err := c.persistState(); err != nil {
			return fmt.Errorf("persist bootstrap administrator: %w", err)
		}
	}
	c.log.Info("bootstrap administrator created", "user", username)
	return nil
}

func (c *Coordinator) authenticate(r *http.Request) (Principal, bool) {
	if authorization := r.Header.Get("Authorization"); strings.HasPrefix(authorization, "Bearer ") {
		secret := strings.TrimPrefix(authorization, "Bearer ")
		if expected := c.cfg.OperatorToken; expected != "" && len(secret) == len(expected) && subtle.ConstantTimeCompare([]byte(secret), []byte(expected)) == 1 {
			return Principal{Actor: strings.TrimSpace(r.Header.Get("X-Parallaxd-Actor")), Role: RoleAdmin, Permissions: permissionsFor(RoleAdmin), Method: "legacy-token"}, true
		}
		hash := secretHash(secret)
		c.authMu.Lock()
		defer c.authMu.Unlock()
		for id, token := range c.apiTokens {
			if token.RevokedAt == nil && subtle.ConstantTimeCompare([]byte(hash), []byte(token.TokenHash)) == 1 {
				now := c.now().UTC()
				token.LastUsedAt = &now
				c.apiTokens[id] = token
				return Principal{Actor: "token:" + token.Name, Role: token.Role, Permissions: permissionsFor(token.Role), Method: "api-token"}, true
			}
		}
		return Principal{}, false
	}
	cookie, err := r.Cookie("parallaxd_session")
	if err != nil || cookie.Value == "" {
		return Principal{}, false
	}
	hash := secretHash(cookie.Value)
	c.authMu.Lock()
	defer c.authMu.Unlock()
	session, ok := c.sessions[hash]
	if !ok || !c.now().Before(session.ExpiresAt) {
		delete(c.sessions, hash)
		return Principal{}, false
	}
	user, ok := c.users[session.Username]
	if !ok || user.Disabled {
		return Principal{}, false
	}
	return Principal{Actor: user.Username, Role: user.Role, Permissions: permissionsFor(user.Role), Method: "session"}, true
}

func (c *Coordinator) requirePermission(w http.ResponseWriter, r *http.Request, permission Permission) (Principal, bool) {
	if !c.authEnabled() {
		http.Error(w, "operator API is disabled", http.StatusServiceUnavailable)
		return Principal{}, false
	}
	principal, ok := c.authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return Principal{}, false
	}
	if !roleAllows(principal.Role, permission) {
		http.Error(w, "permission denied", http.StatusForbidden)
		return Principal{}, false
	}
	if principal.Method == "session" && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
		cookie, _ := r.Cookie("parallaxd_session")
		hash := secretHash(cookie.Value)
		c.authMu.Lock()
		session := c.sessions[hash]
		c.authMu.Unlock()
		provided := secretHash(r.Header.Get("X-Parallaxd-CSRF"))
		if len(provided) != len(session.CSRFHash) || subtle.ConstantTimeCompare([]byte(provided), []byte(session.CSRFHash)) != 1 {
			http.Error(w, "CSRF token required", http.StatusForbidden)
			return Principal{}, false
		}
	}
	return principal, true
}

func mutationActor(principal Principal, supplied string) string {
	if principal.Actor != "" {
		return principal.Actor
	}
	return strings.TrimSpace(supplied)
}

func (c *Coordinator) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.authenticate(r)
	if !ok {
		writeJSON(w, map[string]any{"authenticated": false, "oidc_enabled": c.oidcEnabled(), "oidc_label": c.cfg.OIDC.Label})
		return
	}
	writeJSON(w, map[string]any{"authenticated": true, "username": principal.Actor, "role": principal.Role, "permissions": principal.Permissions, "oidc_enabled": c.oidcEnabled(), "oidc_label": c.cfg.OIDC.Label})
}

func (c *Coordinator) loginLimited(key string) bool {
	now := c.now()
	cutoff := now.Add(-5 * time.Minute)
	c.authMu.Lock()
	defer c.authMu.Unlock()
	attempts := c.loginFailures[key][:0]
	for _, at := range c.loginFailures[key] {
		if at.After(cutoff) {
			attempts = append(attempts, at)
		}
	}
	c.loginFailures[key] = attempts
	return len(attempts) >= 8
}

func (c *Coordinator) recordLoginFailure(key string) {
	c.authMu.Lock()
	c.loginFailures[key] = append(c.loginFailures[key], c.now())
	c.authMu.Unlock()
}

func (c *Coordinator) createSession(w http.ResponseWriter, user User) (Principal, error) {
	secret, err := randomSecret(32)
	if err != nil {
		return Principal{}, err
	}
	csrf, err := randomSecret(24)
	if err != nil {
		return Principal{}, err
	}
	now := c.now().UTC()
	session := Session{TokenHash: secretHash(secret), CSRFHash: secretHash(csrf), Username: user.Username, CreatedAt: now, ExpiresAt: now.Add(c.cfg.SessionTTL)}
	c.authMu.Lock()
	for hash, existing := range c.sessions {
		if !c.now().Before(existing.ExpiresAt) {
			delete(c.sessions, hash)
		}
	}
	// Keep a stolen or forgotten browser from accumulating sessions forever.
	var userSessions []Session
	for _, existing := range c.sessions {
		if existing.Username == user.Username {
			userSessions = append(userSessions, existing)
		}
	}
	if len(userSessions) >= 10 {
		sort.Slice(userSessions, func(i, j int) bool { return userSessions[i].CreatedAt.Before(userSessions[j].CreatedAt) })
		delete(c.sessions, userSessions[0].TokenHash)
	}
	c.sessions[session.TokenHash] = session
	c.authMu.Unlock()
	c.persist()
	secure := !c.cfg.InsecureSessionCookies
	http.SetCookie(w, &http.Cookie{Name: "parallaxd_session", Value: secret, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, Expires: session.ExpiresAt, MaxAge: int(c.cfg.SessionTTL.Seconds())})
	// This is a double-submit convenience for page reloads. The authoritative
	// value remains hashed in the server-side session and every unsafe request
	// must echo it in X-Parallaxd-CSRF.
	http.SetCookie(w, &http.Cookie{Name: "parallaxd_csrf", Value: csrf, Path: "/", HttpOnly: false, Secure: secure, SameSite: http.SameSiteStrictMode, Expires: session.ExpiresAt, MaxAge: int(c.cfg.SessionTTL.Seconds())})
	return Principal{Actor: user.Username, Role: user.Role, Permissions: permissionsFor(user.Role), CSRF: csrf}, nil
}

func (c *Coordinator) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeOperatorJSON(w, r, &body); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(body.Username)
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	key := remote
	if c.loginLimited(key) {
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	c.authMu.Lock()
	user, ok := c.users[username]
	c.authMu.Unlock()
	passwordHash := user.PasswordHash
	if !ok || passwordHash == "" {
		// A real Argon2 calculation keeps unknown-user and wrong-password
		// responses close enough in cost that the endpoint is not a username
		// oracle. The comparison is expected to fail.
		passwordHash = "$argon2id$v=19$m=65536,t=1,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	if !verifyPassword(passwordHash, body.Password) || !ok || user.Disabled {
		c.recordLoginFailure(key)
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}
	principal, err := c.createSession(w, user)
	if err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	c.authMu.Lock()
	delete(c.loginFailures, key)
	c.authMu.Unlock()
	writeJSON(w, principal)
}

func (c *Coordinator) handleLogout(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionView)
	if !ok {
		return
	}
	_ = principal
	if cookie, err := r.Cookie("parallaxd_session"); err == nil {
		c.authMu.Lock()
		delete(c.sessions, secretHash(cookie.Value))
		c.authMu.Unlock()
		c.persist()
	}
	http.SetCookie(w, &http.Cookie{Name: "parallaxd_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: !c.cfg.InsecureSessionCookies, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: "parallaxd_csrf", Path: "/", MaxAge: -1, Secure: !c.cfg.InsecureSessionCookies, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionView)
	if !ok {
		return
	}
	if principal.Method != "session" || principal.Actor == "" {
		http.Error(w, "password changes require a local user session", http.StatusBadRequest)
		return
	}
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeOperatorJSON(w, r, &body); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	c.authMu.Lock()
	user := c.users[principal.Actor]
	c.authMu.Unlock()
	if !verifyPassword(user.PasswordHash, body.CurrentPassword) {
		http.Error(w, "current password is incorrect", http.StatusUnauthorized)
		return
	}
	hash, err := hashPassword(body.NewPassword)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	currentCookie, _ := r.Cookie("parallaxd_session")
	currentHash := secretHash(currentCookie.Value)
	c.authMu.Lock()
	user.PasswordHash = hash
	user.UpdatedAt = c.now().UTC()
	c.users[user.Username] = user
	for sessionHash, session := range c.sessions {
		if session.Username == user.Username && sessionHash != currentHash {
			delete(c.sessions, sessionHash)
		}
	}
	c.authMu.Unlock()
	c.persist()
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) userList() []User {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	out := make([]User, 0, len(c.users))
	for _, user := range c.users {
		user.LocalLogin = user.PasswordHash != ""
		user.PasswordHash = ""
		out = append(out, user)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

func (c *Coordinator) enabledAdminsLocked() int {
	count := 0
	for _, user := range c.users {
		if user.Role == RoleAdmin && !user.Disabled {
			count++
		}
	}
	return count
}

func (c *Coordinator) handleUsers(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionManageAuth)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, c.userList())
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     Role   `json:"role"`
	}
	if err := decodeOperatorJSON(w, r, &body); err != nil || !validUsername(body.Username) || !validRole(body.Role) {
		http.Error(w, "valid username, password, and role are required", http.StatusBadRequest)
		return
	}
	var hash string
	var err error
	if body.Password != "" {
		hash, err = hashPassword(body.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if !c.oidcEnabled() {
		http.Error(w, "password is required when OIDC is not configured", http.StatusBadRequest)
		return
	}
	now := c.now().UTC()
	c.authMu.Lock()
	if _, exists := c.users[body.Username]; exists {
		c.authMu.Unlock()
		http.Error(w, "user already exists", http.StatusConflict)
		return
	}
	user := User{Username: body.Username, Role: body.Role, PasswordHash: hash, CreatedAt: now, UpdatedAt: now}
	c.users[user.Username] = user
	c.authMu.Unlock()
	c.persist()
	c.log.Info("user created", "user", user.Username, "role", user.Role, "actor", principal.Actor)
	w.WriteHeader(http.StatusCreated)
	user.PasswordHash = ""
	user.LocalLogin = hash != ""
	writeJSON(w, user)
}

func (c *Coordinator) handleUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionManageAuth)
	if !ok {
		return
	}
	username := r.PathValue("username")
	c.authMu.Lock()
	user, exists := c.users[username]
	c.authMu.Unlock()
	if !exists {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if r.Method == http.MethodDelete {
		c.authMu.Lock()
		if user.Role == RoleAdmin && !user.Disabled && c.enabledAdminsLocked() <= 1 {
			c.authMu.Unlock()
			http.Error(w, "cannot delete the last enabled administrator", http.StatusConflict)
			return
		}
		delete(c.users, username)
		for hash, session := range c.sessions {
			if session.Username == username {
				delete(c.sessions, hash)
			}
		}
		c.authMu.Unlock()
		c.persist()
		c.log.Info("user deleted", "user", username, "actor", principal.Actor)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var body struct {
		Role     Role   `json:"role"`
		Disabled *bool  `json:"disabled"`
		Password string `json:"password,omitempty"`
	}
	if err := decodeOperatorJSON(w, r, &body); err != nil || !validRole(body.Role) {
		http.Error(w, "valid role is required", http.StatusBadRequest)
		return
	}
	var passwordHash string
	var err error
	if body.Password != "" {
		passwordHash, err = hashPassword(body.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	c.authMu.Lock()
	disabled := user.Disabled
	if body.Disabled != nil {
		disabled = *body.Disabled
	}
	if user.Role == RoleAdmin && !user.Disabled && (body.Role != RoleAdmin || disabled) && c.enabledAdminsLocked() <= 1 {
		c.authMu.Unlock()
		http.Error(w, "cannot disable or demote the last enabled administrator", http.StatusConflict)
		return
	}
	user.Role, user.Disabled, user.UpdatedAt = body.Role, disabled, c.now().UTC()
	if passwordHash != "" {
		user.PasswordHash = passwordHash
	}
	c.users[username] = user
	for hash, session := range c.sessions {
		if session.Username == username && (disabled || passwordHash != "") {
			delete(c.sessions, hash)
		}
	}
	c.authMu.Unlock()
	c.persist()
	c.log.Info("user updated", "user", username, "role", user.Role, "actor", principal.Actor)
	hasLocalLogin := user.PasswordHash != ""
	user.PasswordHash = ""
	user.LocalLogin = hasLocalLogin
	writeJSON(w, user)
}

func (c *Coordinator) tokenList() []APIToken {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	out := make([]APIToken, 0, len(c.apiTokens))
	for _, token := range c.apiTokens {
		token.TokenHash = ""
		out = append(out, token)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (c *Coordinator) handleTokens(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionManageAuth)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, c.tokenList())
		return
	}
	var body struct {
		Name string `json:"name"`
		Role Role   `json:"role"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" || !validRole(body.Role) {
		http.Error(w, "valid name and role are required", http.StatusBadRequest)
		return
	}
	id, err := randomSecret(9)
	if err != nil {
		http.Error(w, "could not create token", http.StatusInternalServerError)
		return
	}
	secretPart, err := randomSecret(32)
	if err != nil {
		http.Error(w, "could not create token", http.StatusInternalServerError)
		return
	}
	secret := "pxd_" + id + "_" + secretPart
	now := c.now().UTC()
	token := APIToken{ID: id, Name: strings.TrimSpace(body.Name), Role: body.Role, Prefix: secret[:min(16, len(secret))], TokenHash: secretHash(secret), CreatedAt: now, CreatedBy: principal.Actor}
	c.authMu.Lock()
	c.apiTokens[id] = token
	c.authMu.Unlock()
	c.persist()
	token.TokenHash = ""
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"token": token, "secret": secret})
}

func (c *Coordinator) handleToken(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionManageAuth)
	if !ok {
		return
	}
	id := r.PathValue("id")
	c.authMu.Lock()
	token, exists := c.apiTokens[id]
	if exists && token.RevokedAt == nil {
		now := c.now().UTC()
		token.RevokedAt = &now
		c.apiTokens[id] = token
	}
	c.authMu.Unlock()
	if !exists {
		http.Error(w, "token not found", http.StatusNotFound)
		return
	}
	c.persist()
	c.log.Info("API token revoked", "token", id, "actor", principal.Actor)
	w.WriteHeader(http.StatusNoContent)
}
