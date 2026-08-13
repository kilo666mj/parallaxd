// Package wgnet creates the WireGuard overlay used by parallaxd's control
// plane. It only renders and installs configuration; the monitoring daemons do
// not receive network-administration privileges.
package wgnet

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const StateVersion = 1

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_=+.-]{1,15}$`)
var nodeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
var endpointHost = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

type Role string

const (
	RoleHub  Role = "hub"
	RolePeer Role = "peer"
)

type KeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

func GenerateKeyPair() (KeyPair, error) {
	priv, pub, err := generateKey()
	return KeyPair{PrivateKey: priv, PublicKey: pub}, err
}

func KeyPairFromPrivate(encoded string) (KeyPair, error) {
	if err := validateKey(strings.TrimSpace(encoded)); err != nil {
		return KeyPair{}, err
	}
	private, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{PrivateKey: strings.TrimSpace(encoded), PublicKey: base64.StdEncoding.EncodeToString(public)}, nil
}

func SaveKeyPair(dir string, pair KeyPair) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return SaveJSON(filepath.Join(dir, "key.json"), pair, 0600)
}

func LoadKeyPair(dir string) (KeyPair, error) {
	var pair KeyPair
	if state, err := LoadState(dir); err == nil {
		return KeyPair{state.PrivateKey, state.PublicKey}, nil
	}
	path := filepath.Join(dir, "key.json")
	info, err := os.Lstat(path)
	if err != nil {
		return pair, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return pair, errors.New("key state must be a private regular file")
	}
	if err := LoadJSON(path, &pair); err != nil {
		return pair, err
	}
	if err := validateKey(pair.PrivateKey); err != nil {
		return pair, err
	}
	private, _ := base64.StdEncoding.DecodeString(pair.PrivateKey)
	derived, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil || base64.StdEncoding.EncodeToString(derived) != pair.PublicKey {
		return pair, errors.New("public key does not match private key")
	}
	return pair, nil
}

// State is private, local node state. PrivateKey must never be exchanged.
type State struct {
	Version    int      `json:"version"`
	Name       string   `json:"name"`
	Role       Role     `json:"role"`
	Interface  string   `json:"interface"`
	Address    string   `json:"address"`
	ListenPort int      `json:"listen_port,omitempty"`
	Endpoint   string   `json:"endpoint,omitempty"`
	PrivateKey string   `json:"private_key"`
	PublicKey  string   `json:"public_key"`
	Overlay    string   `json:"overlay"`
	Hub        *Hub     `json:"hub,omitempty"`
	Peers      []Peer   `json:"peers,omitempty"`
	DNS        []string `json:"dns,omitempty"`
	MTU        int      `json:"mtu,omitempty"`
	Forward    bool     `json:"forward,omitempty"`
}

type Hub struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	Endpoint  string `json:"endpoint"`
}

// Invitation is public hub metadata used to initialize a peer.
type Invitation struct {
	Version   int    `json:"version"`
	Name      string `json:"name"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	Endpoint  string `json:"endpoint"`
	Overlay   string `json:"overlay"`
	Interface string `json:"interface"`
}

// Request is safe to transfer to the hub: it contains no private key.
type Request struct {
	Version   int    `json:"version"`
	Name      string `json:"name"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	Endpoint  string `json:"endpoint,omitempty"`
}

type Peer struct {
	Name                string   `json:"name"`
	Address             string   `json:"address"`
	PublicKey           string   `json:"public_key"`
	Endpoint            string   `json:"endpoint,omitempty"`
	AllowedIPs          []string `json:"allowed_ips,omitempty"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
}

// Topology is the declarative, non-secret desired configuration consumed by
// automation. Reconcile combines it with the locally retained private key.
type Topology struct {
	Version    int    `json:"version"`
	Name       string `json:"name"`
	Role       Role   `json:"role"`
	Interface  string `json:"interface"`
	Address    string `json:"address"`
	Overlay    string `json:"overlay"`
	Endpoint   string `json:"endpoint,omitempty"`
	ListenPort int    `json:"listen_port,omitempty"`
	Forward    bool   `json:"forward,omitempty"`
	Peers      []Peer `json:"peers"`
}

// Reconcile preserves local key material while replacing topology-controlled
// fields with validated desired state.
func Reconcile(current *State, desired Topology) (State, bool, error) {
	var next State
	if desired.Version != StateVersion {
		return next, false, fmt.Errorf("unsupported topology version %d", desired.Version)
	}
	if current == nil {
		priv, pub, err := generateKey()
		if err != nil {
			return next, false, err
		}
		next.PrivateKey, next.PublicKey = priv, pub
	} else {
		next.PrivateKey, next.PublicKey = current.PrivateKey, current.PublicKey
	}
	next.Version, next.Name, next.Role = StateVersion, desired.Name, desired.Role
	next.Interface, next.Address, next.Overlay = desired.Interface, desired.Address, desired.Overlay
	next.Endpoint, next.ListenPort, next.Forward = desired.Endpoint, desired.ListenPort, desired.Forward
	next.Peers = append([]Peer(nil), desired.Peers...)
	sort.Slice(next.Peers, func(i, j int) bool { return next.Peers[i].Name < next.Peers[j].Name })
	if err := next.Validate(); err != nil {
		return State{}, false, err
	}
	before, _ := json.Marshal(current)
	after, _ := json.Marshal(next)
	return next, string(before) != string(after), nil
}

type InitHubOptions struct {
	Name, Interface, Address, Overlay, Endpoint string
	ListenPort, MTU                             int
	DNS                                         []string
}

func InitHub(opts InitHubOptions) (State, Invitation, error) {
	priv, pub, err := generateKey()
	if err != nil {
		return State{}, Invitation{}, err
	}
	s := State{Version: StateVersion, Name: opts.Name, Role: RoleHub, Interface: opts.Interface,
		Address: opts.Address, Overlay: opts.Overlay, Endpoint: opts.Endpoint, ListenPort: opts.ListenPort,
		PrivateKey: priv, PublicKey: pub, MTU: opts.MTU, DNS: opts.DNS, Forward: true}
	if err := s.Validate(); err != nil {
		return State{}, Invitation{}, err
	}
	i := Invitation{Version: StateVersion, Name: s.Name, Address: hostAddress(s.Address), PublicKey: pub,
		Endpoint: s.Endpoint, Overlay: s.Overlay, Interface: s.Interface}
	return s, i, nil
}

type InitPeerOptions struct {
	Name, Address, Endpoint string
	Invitation              Invitation
	MTU                     int
	DNS                     []string
}

func InitPeer(opts InitPeerOptions) (State, Request, error) {
	if err := opts.Invitation.Validate(); err != nil {
		return State{}, Request{}, fmt.Errorf("invitation: %w", err)
	}
	priv, pub, err := generateKey()
	if err != nil {
		return State{}, Request{}, err
	}
	s := State{Version: StateVersion, Name: opts.Name, Role: RolePeer, Interface: opts.Invitation.Interface,
		Address: opts.Address, Overlay: opts.Invitation.Overlay, Endpoint: opts.Endpoint,
		PrivateKey: priv, PublicKey: pub, MTU: opts.MTU, DNS: opts.DNS,
		Hub: &Hub{Name: opts.Invitation.Name, Address: opts.Invitation.Address,
			PublicKey: opts.Invitation.PublicKey, Endpoint: opts.Invitation.Endpoint}}
	if err := s.Validate(); err != nil {
		return State{}, Request{}, err
	}
	r := Request{Version: StateVersion, Name: s.Name, Address: hostAddress(s.Address), PublicKey: pub, Endpoint: s.Endpoint}
	return s, r, nil
}

func (s *State) Authorize(r Request) error {
	if s.Role != RoleHub {
		return errors.New("only a hub can authorize peers")
	}
	if err := r.Validate(s.Overlay); err != nil {
		return err
	}
	if r.Name == s.Name || r.Address == hostAddress(s.Address) {
		return errors.New("peer conflicts with the hub identity or address")
	}
	for i, peer := range s.Peers {
		if peer.Name != r.Name && peer.Address != r.Address && peer.PublicKey != r.PublicKey {
			continue
		}
		if peer.Name != r.Name || peer.Address != r.Address || peer.PublicKey != r.PublicKey {
			return fmt.Errorf("peer conflicts with existing peer %q", peer.Name)
		}
		s.Peers[i].Endpoint = r.Endpoint
		return nil
	}
	s.Peers = append(s.Peers, Peer{Name: r.Name, Address: r.Address, PublicKey: r.PublicKey, Endpoint: r.Endpoint})
	sort.Slice(s.Peers, func(i, j int) bool { return s.Peers[i].Name < s.Peers[j].Name })
	return nil
}

func (s State) Validate() error {
	if s.Version != StateVersion {
		return fmt.Errorf("unsupported state version %d", s.Version)
	}
	if !nodeName.MatchString(s.Name) {
		return errors.New("name must contain only safe DNS-style characters")
	}
	if !interfaceName.MatchString(s.Interface) {
		return errors.New("interface must be 1-15 safe characters")
	}
	if s.Role != RoleHub && s.Role != RolePeer {
		return errors.New("role must be hub or peer")
	}
	addr, err := netip.ParsePrefix(s.Address)
	if err != nil || !addr.Addr().IsValid() {
		return errors.New("address must be a CIDR prefix")
	}
	overlay, err := netip.ParsePrefix(s.Overlay)
	if err != nil || !overlay.Contains(addr.Addr()) {
		return errors.New("address must belong to overlay")
	}
	if err := validateKey(s.PrivateKey); err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	if err := validateKey(s.PublicKey); err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	private, _ := base64.StdEncoding.DecodeString(s.PrivateKey)
	derived, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil || base64.StdEncoding.EncodeToString(derived) != s.PublicKey {
		return errors.New("public key does not match private key")
	}
	if s.ListenPort < 0 || s.ListenPort > 65535 || (s.Role == RoleHub && s.ListenPort == 0) {
		return errors.New("hub listen port must be between 1 and 65535")
	}
	if s.MTU < 0 || (s.MTU > 0 && (s.MTU < 1280 || s.MTU > 9000)) {
		return errors.New("MTU must be between 1280 and 9000")
	}
	for _, server := range s.DNS {
		if _, err := netip.ParseAddr(server); err != nil {
			return errors.New("DNS entries must be IP addresses")
		}
	}
	if s.Role == RoleHub {
		if err := validateEndpoint(s.Endpoint, true); err != nil {
			return err
		}
		for _, p := range s.Peers {
			if err := validatePeer(p, s.Overlay); err != nil {
				return fmt.Errorf("peer %q: %w", p.Name, err)
			}
		}
	} else if s.Hub == nil && len(s.Peers) == 0 {
		return errors.New("peer state requires hub metadata")
	} else if s.Hub != nil {
		if err := (Invitation{Version: StateVersion, Name: s.Hub.Name, Address: s.Hub.Address,
			PublicKey: s.Hub.PublicKey, Endpoint: s.Hub.Endpoint, Overlay: s.Overlay, Interface: s.Interface}).Validate(); err != nil {
			return fmt.Errorf("hub: %w", err)
		}
	} else {
		for _, p := range s.Peers {
			if err := validatePeer(p, s.Overlay); err != nil {
				return fmt.Errorf("peer %q: %w", p.Name, err)
			}
		}
	}
	return nil
}

func (i Invitation) Validate() error {
	if i.Version != StateVersion || !nodeName.MatchString(i.Name) || !interfaceName.MatchString(i.Interface) {
		return errors.New("invalid invitation identity or version")
	}
	if err := validateKey(i.PublicKey); err != nil {
		return err
	}
	overlay, err := netip.ParsePrefix(i.Overlay)
	if err != nil {
		return errors.New("invalid overlay")
	}
	addr, err := netip.ParseAddr(i.Address)
	if err != nil || !overlay.Contains(addr) {
		return errors.New("hub address is outside overlay")
	}
	return validateEndpoint(i.Endpoint, true)
}

func (r Request) Validate(overlayText string) error {
	if r.Version != StateVersion || !nodeName.MatchString(r.Name) {
		return errors.New("invalid enrollment request identity or version")
	}
	if err := validateKey(r.PublicKey); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(r.Address)
	if err != nil {
		return errors.New("peer address must be a bare IP address")
	}
	overlay, err := netip.ParsePrefix(overlayText)
	if err != nil || !overlay.Contains(addr) {
		return errors.New("peer address is outside the overlay")
	}
	return validateEndpoint(r.Endpoint, false)
}

func (s State) Config() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by parallaxd-network. Do not share this file.\n[Interface]\nAddress = %s\nPrivateKey = %s\n", s.Address, s.PrivateKey)
	if s.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", s.ListenPort)
	}
	if s.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", s.MTU)
	}
	if len(s.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(s.DNS, ", "))
	}
	if s.Role == RoleHub {
		for _, p := range s.Peers {
			allowed := p.AllowedIPs
			if len(allowed) == 0 {
				allowed = []string{hostPrefix(p.Address)}
			}
			writePeer(&b, p.Name, p.PublicKey, strings.Join(allowed, ", "), p.Endpoint, p.PersistentKeepalive)
		}
	} else if s.Hub != nil {
		writePeer(&b, s.Hub.Name, s.Hub.PublicKey, s.Overlay, s.Hub.Endpoint, 25)
	} else {
		for _, p := range s.Peers {
			writePeer(&b, p.Name, p.PublicKey, strings.Join(p.AllowedIPs, ", "), p.Endpoint, p.PersistentKeepalive)
		}
	}
	return b.String(), nil
}

func writePeer(b *strings.Builder, name, key, allowed, endpoint string, keepalive int) {
	fmt.Fprintf(b, "\n# %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", name, key, allowed)
	if endpoint != "" {
		fmt.Fprintf(b, "Endpoint = %s\n", endpoint)
	}
	if keepalive > 0 {
		fmt.Fprintf(b, "PersistentKeepalive = %d\n", keepalive)
	}
}

func validatePeer(p Peer, overlayText string) error {
	if !nodeName.MatchString(p.Name) {
		return errors.New("invalid peer name")
	}
	if err := validateKey(p.PublicKey); err != nil {
		return err
	}
	if p.Endpoint != "" {
		if err := validateEndpoint(p.Endpoint, false); err != nil {
			return err
		}
	}
	if p.PersistentKeepalive < 0 || p.PersistentKeepalive > 65535 {
		return errors.New("persistent keepalive is out of range")
	}
	if len(p.AllowedIPs) == 0 {
		if p.Address == "" {
			return errors.New("allowed_ips is required")
		}
		return (Request{Version: StateVersion, Name: p.Name, Address: p.Address, PublicKey: p.PublicKey, Endpoint: p.Endpoint}).Validate(overlayText)
	}
	for _, raw := range p.AllowedIPs {
		if _, err := netip.ParsePrefix(raw); err != nil {
			return errors.New("allowed_ips entries must be CIDR prefixes")
		}
	}
	return nil
}

func SaveJSON(path string, value any, mode os.FileMode) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return atomicWrite(path, raw, mode)
}

func LoadJSON(path string, value any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

// WriteConfig atomically writes a private WireGuard configuration.
func WriteConfig(path, config string) error { return atomicWrite(path, []byte(config), 0600) }

// WritePublicConfig atomically writes non-secret host configuration.
func WritePublicConfig(path, config string) error { return atomicWrite(path, []byte(config), 0644) }

func SaveState(dir string, s State) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return SaveJSON(filepath.Join(dir, "state.json"), s, 0600)
}

func LoadState(dir string) (State, error) {
	var s State
	path := filepath.Join(dir, "state.json")
	info, err := os.Lstat(path)
	if err != nil {
		return s, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return s, errors.New("state must be a regular file, not a link")
	}
	if info.Mode().Perm()&0077 != 0 {
		return s, fmt.Errorf("state permissions %o expose private key; want 0600", info.Mode().Perm())
	}
	if err := LoadJSON(path, &s); err != nil {
		return s, err
	}
	return s, s.Validate()
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".parallaxd-network-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func generateKey() (string, string, error) {
	private := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(private); err != nil {
		return "", "", err
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(public), nil
}

func validateKey(key string) error {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != curve25519.ScalarSize {
		return errors.New("must be a base64-encoded 32-byte WireGuard key")
	}
	return nil
}

func validateEndpoint(endpoint string, required bool) error {
	if endpoint == "" && !required {
		return nil
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return errors.New("endpoint must be host:port")
	}
	if net.ParseIP(host) == nil && !endpointHost.MatchString(host) {
		return errors.New("endpoint host contains unsafe characters")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("endpoint port must be between 1 and 65535")
	}
	return nil
}

func hostAddress(prefix string) string {
	p, _ := netip.ParsePrefix(prefix)
	return p.Addr().String()
}

func hostPrefix(address string) string {
	a, _ := netip.ParseAddr(address)
	bits := 32
	if a.Is6() {
		bits = 128
	}
	return fmt.Sprintf("%s/%d", address, bits)
}
