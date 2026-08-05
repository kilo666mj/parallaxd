// Package wire is the signed protocol between the coordinator and its probers.
//
// Both directions are signed, for different reasons.
//
// A prober's result is a claim about the world, and the coordinator counts it
// toward a verdict. Quorum de-duplication trusts the prober name on a result;
// if that name is an unauthenticated string, anything that can reach the
// coordinator can manufacture agreement and alert on a healthy service, or
// forge "up" results and suppress a real outage.
//
// A coordinator's request tells a prober to make a network connection to an
// arbitrary target, right now. An unauthenticated version of that turns the
// fleet into a probe amplifier: one request fans out to every prober, aimed
// wherever the sender likes. Requiring a signature the probers already trust
// keeps a monitoring system from becoming an attack tool.
//
// The bytes that are signed are the bytes that are transmitted. Nothing
// re-serializes a payload and hopes it matches — a verifier that re-marshals
// before checking is one library upgrade away from rejecting valid messages,
// or worse, accepting altered ones.
package wire

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

// Domain separation. A signature over one kind of message must never verify
// as another, or a captured result could be replayed as a request to probe
// something.
const (
	domainResult  = "parallaxd/result/v1\x00"
	domainRequest = "parallaxd/request/v1\x00"
)

// maxClockSkew bounds how far in the future a signed message may claim to be.
// Probers sign with their own clocks, and a wildly wrong one should be a
// visible error rather than a message that silently outlives every staleness
// check applied to it.
const maxClockSkew = 2 * time.Minute

var (
	ErrBadSignature  = errors.New("signature does not verify")
	ErrUnknownPeer   = errors.New("no public key registered for peer")
	ErrIdentity      = errors.New("signed payload disagrees with the envelope")
	ErrExpired       = errors.New("message expired")
	ErrFromTheFuture = errors.New("message timestamped too far in the future")
)

// Envelope carries a signed payload. Payload is the exact byte sequence that
// was signed and must be verified before being decoded.
type Envelope struct {
	// Peer is who claims to have sent this. It selects the public key; the
	// signature then proves the claim. It is never trusted on its own.
	Peer string `json:"peer"`

	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// Request is the coordinator asking a prober to run a check immediately.
type Request struct {
	// ID is a nonce echoed in the result, so a result can only satisfy the
	// request it was produced for. Without it an old "down" can be replayed
	// to trigger a fresh alert.
	ID string `json:"id"`

	Check check.Check `json:"check"`

	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ResultPayload is what a prober signs: the result plus the request it
// answers. Protocol concerns live here rather than in check.Result, which
// stays a plain domain object.
type ResultPayload struct {
	Result check.Result `json:"result"`

	// RequestID is empty for a scheduled probe and set when answering a
	// corroboration request.
	RequestID string `json:"request_id,omitempty"`
}

// Keyring maps peer names to the public keys that authenticate them.
type Keyring struct {
	keys map[string]ed25519.PublicKey
}

// NewKeyring returns an empty keyring.
func NewKeyring() *Keyring { return &Keyring{keys: map[string]ed25519.PublicKey{}} }

// Add registers a peer's public key.
func (k *Keyring) Add(peer string, pub ed25519.PublicKey) error {
	if peer == "" {
		return errors.New("peer name is required")
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("peer %q: public key is %d bytes, want %d",
			peer, len(pub), ed25519.PublicKeySize)
	}
	k.keys[peer] = pub
	return nil
}

// Peers lists the registered peer names.
func (k *Keyring) Peers() []string {
	out := make([]string, 0, len(k.keys))
	for p := range k.keys {
		out = append(out, p)
	}
	return out
}

func (k *Keyring) verify(domain string, e Envelope) error {
	pub, ok := k.keys[e.Peer]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownPeer, e.Peer)
	}
	if !ed25519.Verify(pub, signedBytes(domain, e.Payload), e.Signature) {
		return fmt.Errorf("%w: peer %q", ErrBadSignature, e.Peer)
	}
	return nil
}

func signedBytes(domain string, payload []byte) []byte {
	out := make([]byte, 0, len(domain)+len(payload))
	out = append(out, domain...)
	return append(out, payload...)
}

func seal(priv ed25519.PrivateKey, domain, peer string, v any) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("private key is %d bytes, want %d",
			len(priv), ed25519.PrivateKeySize)
	}
	payload, err := json.Marshal(v)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Peer:      peer,
		Payload:   payload,
		Signature: ed25519.Sign(priv, signedBytes(domain, payload)),
	}, nil
}

// SignResult produces a signed result from a prober.
func SignResult(priv ed25519.PrivateKey, p ResultPayload) (Envelope, error) {
	if p.Result.Prober == "" {
		return Envelope{}, errors.New("result has no prober name")
	}
	return seal(priv, domainResult, p.Result.Prober, p)
}

// OpenResult verifies a result envelope and returns its payload.
//
// now is passed in rather than read from the clock so the caller controls
// time, which keeps this testable and keeps skew policy in one place.
func (k *Keyring) OpenResult(e Envelope, now time.Time) (ResultPayload, error) {
	if err := k.verify(domainResult, e); err != nil {
		return ResultPayload{}, err
	}
	var p ResultPayload
	if err := json.Unmarshal(e.Payload, &p); err != nil {
		return ResultPayload{}, fmt.Errorf("decode result: %w", err)
	}
	// The signature proves who signed the bytes; this proves the bytes claim
	// the same identity. Otherwise a prober could sign a result attributed to
	// someone else and have it counted as a second opinion.
	if p.Result.Prober != e.Peer {
		return ResultPayload{}, fmt.Errorf("%w: envelope says %q, result says %q",
			ErrIdentity, e.Peer, p.Result.Prober)
	}
	if !now.IsZero() && p.Result.At.After(now.Add(maxClockSkew)) {
		return ResultPayload{}, fmt.Errorf("%w: result timestamped %s, now is %s",
			ErrFromTheFuture, p.Result.At.UTC(), now.UTC())
	}
	return p, nil
}

// SignRequest produces a signed corroboration request from the coordinator.
func SignRequest(priv ed25519.PrivateKey, coordinator string, r Request) (Envelope, error) {
	switch {
	case coordinator == "":
		return Envelope{}, errors.New("coordinator name is required")
	case r.ID == "":
		return Envelope{}, errors.New("request has no id; a result could then " +
			"be replayed against any later request")
	case r.ExpiresAt.IsZero():
		return Envelope{}, errors.New("request has no expiry; a captured request " +
			"would be replayable forever")
	}
	return seal(priv, domainRequest, coordinator, r)
}

// OpenRequest verifies a request envelope. A prober calls this before making
// any connection, so an unsigned or expired instruction never causes traffic.
func (k *Keyring) OpenRequest(e Envelope, now time.Time) (Request, error) {
	if err := k.verify(domainRequest, e); err != nil {
		return Request{}, err
	}
	var r Request
	if err := json.Unmarshal(e.Payload, &r); err != nil {
		return Request{}, fmt.Errorf("decode request: %w", err)
	}
	if !now.IsZero() && now.After(r.ExpiresAt) {
		return Request{}, fmt.Errorf("%w: expired at %s", ErrExpired, r.ExpiresAt.UTC())
	}
	if err := r.Check.Validate(); err != nil {
		return Request{}, fmt.Errorf("request carries an invalid check: %w", err)
	}
	return r, nil
}

// NewRequestID returns a random nonce.
func NewRequestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// GenerateKey creates a keypair for a peer.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// EncodeKey renders a key for a config file.
func EncodeKey(key []byte) string { return base64.StdEncoding.EncodeToString(key) }

// DecodePublicKey parses a public key from a config file.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// DecodePrivateKey parses a private key from a config file.
func DecodePrivateKey(s string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key is %d bytes, want %d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}
