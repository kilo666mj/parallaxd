package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineEnrollmentWorkflow(t *testing.T) {
	root := t.TempDir()
	hub := filepath.Join(root, "hub")
	peer := filepath.Join(root, "peer")
	var out, errOut bytes.Buffer
	if err := run([]string{"hub-init", "--state", hub, "--endpoint", "hub.example.com:51821"}, &out, &errOut); err != nil {
		t.Fatalf("hub-init: %v (%s)", err, errOut.String())
	}
	if err := run([]string{"peer-init", "--state", peer, "--invitation", filepath.Join(hub, "invitation.json"),
		"--name", "probe-a", "--address", "10.77.0.10/24"}, &out, &errOut); err != nil {
		t.Fatalf("peer-init: %v (%s)", err, errOut.String())
	}
	if err := run([]string{"authorize", "--state", hub, "--request", filepath.Join(peer, "enrollment.json")}, &out, &errOut); err != nil {
		t.Fatalf("authorize: %v (%s)", err, errOut.String())
	}
	for _, item := range []struct{ state, output string }{{hub, filepath.Join(root, "hub.conf")}, {peer, filepath.Join(root, "peer.conf")}} {
		if err := run([]string{"render", "--state", item.state, "--output", item.output}, &out, &errOut); err != nil {
			t.Fatalf("render: %v (%s)", err, errOut.String())
		}
		raw, err := os.ReadFile(item.output)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "[Interface]") || !strings.Contains(string(raw), "[Peer]") {
			t.Fatalf("incomplete config:\n%s", raw)
		}
	}
	if err := run([]string{"peer-init", "--state", peer, "--invitation", filepath.Join(hub, "invitation.json"),
		"--name", "probe-a", "--address", "10.77.0.10/24"}, &out, &errOut); err == nil {
		t.Fatal("peer-init replaced an existing private key")
	}
}

func TestAutomationReconcileWorkflow(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	var out, errOut bytes.Buffer
	if err := run([]string{"key-init", "--state", state}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	public := strings.TrimSpace(out.String())
	out.Reset()
	topology := filepath.Join(dir, "topology.json")
	raw := `{"version":1,"name":"coordinator","role":"hub","interface":"wg-parallaxd","address":"10.77.0.1/32","overlay":"10.77.0.0/24","endpoint":"hub.example:51821","listen_port":51821,"peers":[]}`
	if err := os.WriteFile(topology, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"reconcile", "--state", state, "--topology", topology}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"changed":true`) {
		t.Fatalf("first reconcile: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"reconcile", "--state", state, "--topology", topology}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"changed":false`) {
		t.Fatalf("second reconcile: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"public-key", "--state", state}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != public {
		t.Fatal("reconcile changed automation public key")
	}
}
