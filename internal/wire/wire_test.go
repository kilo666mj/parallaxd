package wire

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/mesh"
)

var now = time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

func testCheck() check.Check {
	return check.Check{
		Name: "mx-smtps", Kind: check.KindTCP, Target: "mx.example.com:465",
		Vantage: check.VantagePublic, Interval: time.Minute, Timeout: 10 * time.Second,
		Quorum: check.Quorum{Agree: 2, Of: 3},
	}
}

func testResult(prober string) check.Result {
	return check.Result{
		Check: "mx-smtps", Prober: prober, Provider: "hetzner",
		Vantage: check.VantagePublic, Status: check.StatusDown, At: now,
	}
}

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func ringWith(t *testing.T, peer string, pub ed25519.PublicKey) *Keyring {
	t.Helper()
	k := NewKeyring()
	if err := k.Add(peer, pub); err != nil {
		t.Fatalf("Add: %v", err)
	}
	return k
}

func TestResultRoundTrip(t *testing.T) {
	pub, priv := keypair(t)
	ring := ringWith(t, "probe-a", pub)

	env, err := SignResult(priv, ResultPayload{Result: testResult("probe-a"), RequestID: "req-1"})
	if err != nil {
		t.Fatalf("SignResult: %v", err)
	}
	if env.Peer != "probe-a" {
		t.Errorf("peer = %q", env.Peer)
	}

	got, err := ring.OpenResult(env, now)
	if err != nil {
		t.Fatalf("OpenResult: %v", err)
	}
	if got.Result.Status != check.StatusDown || got.RequestID != "req-1" {
		t.Errorf("payload = %+v", got)
	}
}

func TestRequestRoundTrip(t *testing.T) {
	pub, priv := keypair(t)
	ring := ringWith(t, "coordinator", pub)

	env, err := SignRequest(priv, "coordinator", Request{
		ID: "req-1", Prober: "probe-a", Check: testCheck(),
		IssuedAt: now, ExpiresAt: now.Add(30 * time.Second),
	})
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	got, err := ring.OpenRequest(env, now)
	if err != nil {
		t.Fatalf("OpenRequest: %v", err)
	}
	if got.Check.Target != "mx.example.com:465" || got.ID != "req-1" {
		t.Errorf("request = %+v", got)
	}
}

// The core property: altering any signed byte must invalidate the signature.
func TestTamperedPayloadIsRejected(t *testing.T) {
	pub, priv := keypair(t)
	ring := ringWith(t, "probe-a", pub)

	env, err := SignResult(priv, ResultPayload{Result: testResult("probe-a")})
	if err != nil {
		t.Fatalf("SignResult: %v", err)
	}

	// Flip the verdict from down to up — the exact edit an attacker wanting
	// to suppress an outage would make.
	var p ResultPayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	p.Result.Status = check.StatusUp
	altered, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	env.Payload = altered

	if _, err := ring.OpenResult(env, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

func TestUnknownPeerIsRejected(t *testing.T) {
	_, priv := keypair(t)
	env, err := SignResult(priv, ResultPayload{Result: testResult("probe-stranger")})
	if err != nil {
		t.Fatalf("SignResult: %v", err)
	}
	if _, err := NewKeyring().OpenResult(env, now); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("err = %v, want ErrUnknownPeer", err)
	}
}

// A valid signature from the wrong key must not pass just because the peer
// name is registered.
func TestWrongKeyIsRejected(t *testing.T) {
	realPub, _ := keypair(t)
	_, attackerPriv := keypair(t)
	ring := ringWith(t, "probe-a", realPub)

	env, err := SignResult(attackerPriv, ResultPayload{Result: testResult("probe-a")})
	if err != nil {
		t.Fatalf("SignResult: %v", err)
	}
	if _, err := ring.OpenResult(env, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

// A prober must not be able to sign a result attributed to a different
// prober: quorum counts one vote per name, so that would let one node
// manufacture agreement with itself.
func TestIdentityMustMatchTheEnvelope(t *testing.T) {
	pub, priv := keypair(t)
	ring := ringWith(t, "probe-a", pub)

	// Sign a payload whose inner prober claims to be someone else, while the
	// envelope correctly says probe-a so the signature verifies.
	env, err := seal(priv, domainResult, "probe-a",
		ResultPayload{Result: testResult("probe-b")})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := ring.OpenResult(env, now); !errors.Is(err, ErrIdentity) {
		t.Fatalf("err = %v, want ErrIdentity", err)
	}
}

// Domain separation: a captured result must not verify as a request, or a
// replayed message could instruct probers to connect somewhere.
func TestCrossTypeReplayIsRejected(t *testing.T) {
	pub, priv := keypair(t)
	ring := ringWith(t, "peer", pub)

	resultEnv, err := seal(priv, domainResult, "peer", ResultPayload{Result: testResult("peer")})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := ring.OpenRequest(resultEnv, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a result verified as a request: %v", err)
	}

	reqEnv, err := seal(priv, domainRequest, "peer", Request{
		ID: "r", Prober: "probe-a", Check: testCheck(), ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := ring.OpenResult(reqEnv, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a request verified as a result: %v", err)
	}
}

// A captured request replayed later must not cause probe traffic.
func TestExpiredRequestIsRejected(t *testing.T) {
	pub, priv := keypair(t)
	ring := ringWith(t, "coordinator", pub)

	env, err := SignRequest(priv, "coordinator", Request{
		ID: "req-1", Prober: "probe-a", Check: testCheck(),
		IssuedAt: now, ExpiresAt: now.Add(30 * time.Second),
	})
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if _, err := ring.OpenRequest(env, now.Add(time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	if _, err := ring.OpenRequest(env, now.Add(10*time.Second)); err != nil {
		t.Errorf("a still-valid request was rejected: %v", err)
	}
}

// An unsigned request must never reach the point of making a connection, and
// a signed one carrying nonsense must not either.
func TestRequestWithInvalidCheckIsRejected(t *testing.T) {
	pub, priv := keypair(t)
	ring := ringWith(t, "coordinator", pub)

	bad := testCheck()
	bad.Vantage = "" // the field that makes corroboration meaningful
	env, err := SignRequest(priv, "coordinator", Request{
		ID: "req-1", Prober: "probe-a", Check: bad, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if _, err := ring.OpenRequest(env, now); err == nil {
		t.Fatal("a request carrying an invalid check was accepted")
	}
}

// A request with no nonce would let any later result be replayed against it.
func TestRequestRequiresIDAndExpiry(t *testing.T) {
	_, priv := keypair(t)
	if _, err := SignRequest(priv, "coordinator", Request{
		Prober: "probe-a", Check: testCheck(), ExpiresAt: now.Add(time.Minute),
	}); err == nil {
		t.Error("a request with no id was signed")
	}
	if _, err := SignRequest(priv, "coordinator", Request{
		ID: "x", Prober: "probe-a", Check: testCheck(),
	}); err == nil {
		t.Error("a request with no expiry was signed")
	}
}

// A prober with a badly wrong clock would otherwise produce results that
// outlive every staleness check applied downstream.
func TestFutureDatedResultIsRejected(t *testing.T) {
	pub, priv := keypair(t)
	ring := ringWith(t, "probe-a", pub)

	r := testResult("probe-a")
	r.At = now.Add(time.Hour)
	env, err := SignResult(priv, ResultPayload{Result: r})
	if err != nil {
		t.Fatalf("SignResult: %v", err)
	}
	if _, err := ring.OpenResult(env, now); !errors.Is(err, ErrFromTheFuture) {
		t.Fatalf("err = %v, want ErrFromTheFuture", err)
	}

	// Modest skew is tolerated; clocks are never exactly aligned.
	r.At = now.Add(30 * time.Second)
	env, err = SignResult(priv, ResultPayload{Result: r})
	if err != nil {
		t.Fatalf("SignResult: %v", err)
	}
	if _, err := ring.OpenResult(env, now); err != nil {
		t.Errorf("modest clock skew was rejected: %v", err)
	}
}

func TestHeartbeatRejectsForgeryAndClockPoisoning(t *testing.T) {
	pub, priv := keypair(t)
	ring := ringWith(t, "coordinator", pub)
	env, err := SignHeartbeat(priv, Heartbeat{Coordinator: "coordinator", At: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.OpenHeartbeat(env, now, time.Minute); !errors.Is(err, ErrFromTheFuture) {
		t.Fatalf("future heartbeat err=%v", err)
	}
	env, err = SignHeartbeat(priv, Heartbeat{Coordinator: "coordinator", At: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.OpenHeartbeat(env, now, time.Minute); !errors.Is(err, ErrExpired) {
		t.Fatalf("old heartbeat err=%v", err)
	}
	env.Signature[0] ^= 1
	if _, err := ring.OpenHeartbeat(env, now, time.Hour*2); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged heartbeat err=%v", err)
	}
}

func TestKeyEncoding(t *testing.T) {
	pub, priv := keypair(t)

	gotPub, err := DecodePublicKey(EncodeKey(pub))
	if err != nil || !gotPub.Equal(pub) {
		t.Fatalf("public key round trip: %v", err)
	}
	gotPriv, err := DecodePrivateKey(EncodeKey(priv))
	if err != nil || !gotPriv.Equal(priv) {
		t.Fatalf("private key round trip: %v", err)
	}

	// A truncated or mistyped key must fail loudly at load rather than
	// producing signatures nobody can verify.
	if _, err := DecodePublicKey(EncodeKey(pub[:16])); err == nil {
		t.Error("a short public key was accepted")
	}
	if _, err := DecodePublicKey("not base64!"); err == nil {
		t.Error("non-base64 was accepted as a key")
	}
	if _, err := DecodePrivateKey(EncodeKey(pub)); err == nil {
		t.Error("a public key was accepted as a private key")
	}
}

func TestKeyringValidation(t *testing.T) {
	pub, _ := keypair(t)
	k := NewKeyring()
	if err := k.Add("", pub); err == nil {
		t.Error("a peer with no name was registered")
	}
	if err := k.Add("p", pub[:8]); err == nil {
		t.Error("a truncated key was registered")
	}
	if err := k.Add("p", pub); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if peers := k.Peers(); len(peers) != 1 || peers[0] != "p" {
		t.Errorf("peers = %v", peers)
	}
}

func TestSignRejectsBadPrivateKey(t *testing.T) {
	if _, err := SignResult(ed25519.PrivateKey("short"), ResultPayload{Result: testResult("a")}); err == nil {
		t.Error("a malformed private key produced a signature")
	}
	_, priv := keypair(t)
	if _, err := SignResult(priv, ResultPayload{Result: check.Result{}}); err == nil {
		t.Error("a result with no prober name was signed")
	}
}

func TestNewRequestIDIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id, err := NewRequestID()
		if err != nil {
			t.Fatalf("NewRequestID: %v", err)
		}
		if seen[id] {
			t.Fatalf("duplicate request id %q", id)
		}
		seen[id] = true
	}
}

// An envelope arrives from the network and its payload length is the one
// field an unauthenticated sender fully controls. It must be refused before
// anything is allocated from it, and before the key lookup — otherwise a
// stranger can make the coordinator allocate on demand.
func TestOversizedPayloadIsRefused(t *testing.T) {
	pub, priv := keypair(t)
	ring := ringWith(t, "probe-a", pub)

	env, err := SignResult(priv, ResultPayload{Result: testResult("probe-a")})
	if err != nil {
		t.Fatalf("SignResult: %v", err)
	}
	env.Payload = make([]byte, MaxPayloadBytes+1)

	if _, err := ring.OpenResult(env, now); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("err = %v, want ErrPayloadTooLarge", err)
	}

	// Rejected even for a peer nobody has heard of, so the size check cannot
	// be skipped by claiming an unregistered identity.
	env.Peer = "stranger"
	if _, err := ring.OpenResult(env, now); !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("err = %v, want the size checked before the key lookup", err)
	}

	// The same guard protects the request path.
	reqEnv, err := SignRequest(priv, "probe-a", Request{
		ID: "r", Prober: "probe-a", Check: testCheck(), ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	reqEnv.Payload = make([]byte, MaxPayloadBytes+1)
	if _, err := ring.OpenRequest(reqEnv, now); !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("err = %v, want ErrPayloadTooLarge on the request path", err)
	}
}

func TestDocumentSigning(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ring := NewKeyring()
	if err := ring.Add("coordinator", pub); err != nil {
		t.Fatalf("Add: %v", err)
	}

	doc := map[string]any{"components": []string{"email"}}
	env, err := SignDocument(priv, "coordinator", doc)
	if err != nil {
		t.Fatalf("SignDocument: %v", err)
	}

	raw, err := ring.OpenDocument(env)
	if err != nil {
		t.Fatalf("OpenDocument: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("decoded = %v", got)
	}

	if _, err := SignDocument(priv, "", doc); err == nil {
		t.Error("SignDocument accepted an empty publisher")
	}
}

// A document must not verify as a request. Otherwise a published export —
// which is world-readable by design — could be replayed at a prober as an
// instruction to connect somewhere.
func TestDocumentIsDomainSeparated(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ring := NewKeyring()
	if err := ring.Add("coordinator", pub); err != nil {
		t.Fatalf("Add: %v", err)
	}

	env, err := SignDocument(priv, "coordinator", map[string]string{"x": "y"})
	if err != nil {
		t.Fatalf("SignDocument: %v", err)
	}
	if _, err := ring.OpenRequest(env, time.Now()); !errors.Is(err, ErrBadSignature) {
		t.Errorf("OpenRequest on a document = %v, want %v", err, ErrBadSignature)
	}
	if _, err := ring.OpenResult(env, time.Now()); !errors.Is(err, ErrBadSignature) {
		t.Errorf("OpenResult on a document = %v, want %v", err, ErrBadSignature)
	}

	// And the reverse: a signed request must not pass as a published document.
	id, _ := NewRequestID()
	req, err := SignRequest(priv, "coordinator", Request{
		ID: id, Prober: "probe-a", Check: testCheck(), IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if _, err := ring.OpenDocument(req); !errors.Is(err, ErrBadSignature) {
		t.Errorf("OpenDocument on a request = %v, want %v", err, ErrBadSignature)
	}
}

func TestMeshReportSigning(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ring := NewKeyring()
	if err := ring.Add("probe-a", pub); err != nil {
		t.Fatalf("Add: %v", err)
	}

	r := mesh.Report{Prober: "probe-a", At: now, Peers: []mesh.PeerView{
		{Peer: "probe-b", Reachable: true},
		{Peer: "probe-c", Reachable: false, Detail: "connection refused"},
	}}
	env, err := SignMeshReport(priv, r)
	if err != nil {
		t.Fatalf("SignMeshReport: %v", err)
	}

	got, err := ring.OpenMeshReport(env, now)
	if err != nil {
		t.Fatalf("OpenMeshReport: %v", err)
	}
	if got.Prober != "probe-a" || len(got.Peers) != 2 || got.Reached() != 1 {
		t.Fatalf("decoded = %+v", got)
	}

	if _, err := SignMeshReport(priv, mesh.Report{At: now}); err == nil {
		t.Error("SignMeshReport accepted a report with no prober name")
	}
}

// A mesh report silences a prober, so one prober signing on another's behalf
// would be a way to suppress an opinion — which is how a real outage goes
// unreported.
func TestMeshReportIdentityIsBound(t *testing.T) {
	pubA, privA, _ := GenerateKey()
	pubB, _, _ := GenerateKey()
	ring := NewKeyring()
	if err := ring.Add("probe-a", pubA); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := ring.Add("probe-b", pubB); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// probe-a signs, but the envelope claims probe-b.
	env, err := SignMeshReport(privA, mesh.Report{Prober: "probe-a", At: now})
	if err != nil {
		t.Fatalf("SignMeshReport: %v", err)
	}
	env.Peer = "probe-b"
	if _, err := ring.OpenMeshReport(env, now); !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want %v", err, ErrBadSignature)
	}
}

// A report must not verify as a result or a request, or a captured one could
// be replayed to make probers connect somewhere.
func TestMeshReportIsDomainSeparated(t *testing.T) {
	pub, priv, _ := GenerateKey()
	ring := NewKeyring()
	if err := ring.Add("probe-a", pub); err != nil {
		t.Fatalf("Add: %v", err)
	}

	env, err := SignMeshReport(priv, mesh.Report{Prober: "probe-a", At: now})
	if err != nil {
		t.Fatalf("SignMeshReport: %v", err)
	}
	if _, err := ring.OpenResult(env, now); !errors.Is(err, ErrBadSignature) {
		t.Errorf("OpenResult on a mesh report = %v, want %v", err, ErrBadSignature)
	}
	if _, err := ring.OpenRequest(env, now); !errors.Is(err, ErrBadSignature) {
		t.Errorf("OpenRequest on a mesh report = %v, want %v", err, ErrBadSignature)
	}
	if _, err := ring.OpenDocument(env); !errors.Is(err, ErrBadSignature) {
		t.Errorf("OpenDocument on a mesh report = %v, want %v", err, ErrBadSignature)
	}
}

func TestMeshReportFromTheFutureIsRejected(t *testing.T) {
	pub, priv, _ := GenerateKey()
	ring := NewKeyring()
	if err := ring.Add("probe-a", pub); err != nil {
		t.Fatalf("Add: %v", err)
	}
	env, err := SignMeshReport(priv, mesh.Report{Prober: "probe-a", At: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("SignMeshReport: %v", err)
	}
	if _, err := ring.OpenMeshReport(env, now); !errors.Is(err, ErrFromTheFuture) {
		t.Errorf("err = %v, want %v", err, ErrFromTheFuture)
	}
}
