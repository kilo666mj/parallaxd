package wgnet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testHub(t *testing.T) (State, Invitation) {
	t.Helper()
	s, invitation, err := InitHub(InitHubOptions{Name: "coordinator", Interface: "wg-parallaxd",
		Address: "10.77.0.1/24", Overlay: "10.77.0.0/24", Endpoint: "monitor.example.com:51821", ListenPort: 51821})
	if err != nil {
		t.Fatal(err)
	}
	return s, invitation
}

func TestEnrollmentNeverExportsPrivateKeys(t *testing.T) {
	hub, invitation := testHub(t)
	peer, request, err := InitPeer(InitPeerOptions{Name: "probe-a", Address: "10.77.0.10/24", Invitation: invitation})
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"invitation": invitation, "request": request} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), hub.PrivateKey) || strings.Contains(string(raw), peer.PrivateKey) || strings.Contains(string(raw), "private_key") {
			t.Fatalf("%s leaked private key material: %s", name, raw)
		}
	}
}

func TestAuthorizeAndRenderHubAndPeer(t *testing.T) {
	hub, invitation := testHub(t)
	peer, request, err := InitPeer(InitPeerOptions{Name: "probe-a", Address: "10.77.0.10/24", Invitation: invitation})
	if err != nil {
		t.Fatal(err)
	}
	if err := hub.Authorize(request); err != nil {
		t.Fatal(err)
	}
	hubConfig, err := hub.Config()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PrivateKey = " + hub.PrivateKey, "PublicKey = " + peer.PublicKey, "AllowedIPs = 10.77.0.10/32"} {
		if !strings.Contains(hubConfig, want) {
			t.Errorf("hub config lacks %q:\n%s", want, hubConfig)
		}
	}
	peerConfig, err := peer.Config()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PrivateKey = " + peer.PrivateKey, "PublicKey = " + hub.PublicKey,
		"AllowedIPs = 10.77.0.0/24", "Endpoint = monitor.example.com:51821", "PersistentKeepalive = 25"} {
		if !strings.Contains(peerConfig, want) {
			t.Errorf("peer config lacks %q:\n%s", want, peerConfig)
		}
	}
}

func TestAuthorizeRejectsConflictsAndOutsideAddresses(t *testing.T) {
	hub, invitation := testHub(t)
	_, first, err := InitPeer(InitPeerOptions{Name: "probe-a", Address: "10.77.0.10/24", Invitation: invitation})
	if err != nil {
		t.Fatal(err)
	}
	if err := hub.Authorize(first); err != nil {
		t.Fatal(err)
	}
	_, conflicting, err := InitPeer(InitPeerOptions{Name: "probe-b", Address: "10.77.0.10/24", Invitation: invitation})
	if err != nil {
		t.Fatal(err)
	}
	if err := hub.Authorize(conflicting); err == nil {
		t.Fatal("accepted a duplicate overlay address")
	}
	conflicting.Address = "10.88.0.10"
	if err := hub.Authorize(conflicting); err == nil {
		t.Fatal("accepted an address outside the overlay")
	}
}

func TestEnrollmentFieldsCannotInjectWireGuardConfiguration(t *testing.T) {
	hub, invitation := testHub(t)
	_, request, err := InitPeer(InitPeerOptions{Name: "probe-a", Address: "10.77.0.10/24", Invitation: invitation})
	if err != nil {
		t.Fatal(err)
	}
	request.Name = "probe-a\nPostUp=touch /tmp/owned"
	if err := hub.Authorize(request); err == nil {
		t.Fatal("accepted a newline in a peer name")
	}
	request.Name = "probe-a"
	request.Endpoint = "host\n.example:51821"
	if err := hub.Authorize(request); err == nil {
		t.Fatal("accepted a newline in an endpoint")
	}
}

func TestStateIsPrivateAndUnknownFieldsAreRejected(t *testing.T) {
	hub, _ := testHub(t)
	dir := filepath.Join(t.TempDir(), "state")
	if err := SaveState(dir, hub); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state mode = %o, want 600", info.Mode().Perm())
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"version":1,"surprise":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	var invitation Invitation
	if err := LoadJSON(bad, &invitation); err == nil {
		t.Fatal("accepted an unknown enrollment field")
	}
}

func TestReconcilePreservesKeysAndIsIdempotent(t *testing.T) {
	pair, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	current := State{Version: StateVersion, Name: "old", Role: RoleHub, Interface: "wg-parallaxd", Address: "10.77.0.1/24", Overlay: "10.77.0.0/24", Endpoint: "old.example:51821", ListenPort: 51821, PrivateKey: pair.PrivateKey, PublicKey: pair.PublicKey}
	peerPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	topology := Topology{Version: 1, Name: "coordinator", Role: RoleHub, Interface: "wg-parallaxd", Address: "10.77.0.1/32", Overlay: "10.77.0.0/24", Endpoint: "hub.example:51821", ListenPort: 51821, Peers: []Peer{{Name: "probe-a", Address: "10.77.0.10", PublicKey: peerPair.PublicKey, AllowedIPs: []string{"10.77.0.10/32"}}}}
	next, changed, err := Reconcile(&current, topology)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("changed topology reported unchanged")
	}
	if next.PrivateKey != pair.PrivateKey || next.PublicKey != pair.PublicKey {
		t.Fatal("reconcile rotated local keys")
	}
	again, changed, err := Reconcile(&next, topology)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("identical topology was not idempotent")
	}
	if again.PrivateKey != pair.PrivateKey {
		t.Fatal("idempotent reconcile rotated key")
	}
}
