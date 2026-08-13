// Command parallaxd-network creates and installs parallaxd's encrypted control
// overlay. Key generation and enrollment are unprivileged; only install needs
// root because it writes /etc/wireguard and invokes systemd.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kilo666mj/parallaxd/internal/wgnet"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "parallaxd-network:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return errors.New("a command is required")
	}
	switch args[0] {
	case "key-init":
		return keyInit(args[1:], stdout, stderr)
	case "public-key":
		return publicKey(args[1:], stdout, stderr)
	case "reconcile":
		return reconcile(args[1:], stdout, stderr)
	case "hub-init":
		return hubInit(args[1:], stdout, stderr)
	case "peer-init":
		return peerInit(args[1:], stdout, stderr)
	case "authorize":
		return authorize(args[1:], stdout, stderr)
	case "render":
		return render(args[1:], stdout, stderr)
	case "install":
		return install(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		fmt.Fprintln(stdout, version)
		return nil
	case "help", "-h", "--help":
		usage(stdout)
		return nil
	default:
		usage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `Usage: parallaxd-network COMMAND [options]

Commands:
  key-init   Ensure a local automation keypair exists
  public-key Print the local automation public key
  reconcile  Reconcile private state from a declarative topology
  hub-init   Create a hub key, private state, and public invitation
  peer-init  Create a peer key, private state, and public enrollment request
  authorize  Add or update an enrollment request in hub state
  render     Write the node's private WireGuard configuration
  install    Validate, install, enable, and restart the WireGuard interface

Private state never leaves its node. Transfer only invitation.json from the
hub and enrollment.json from a peer.`)
}

func keyInit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("key-init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state", "/var/lib/parallaxd/network", "private state directory")
	check := fs.Bool("check", false, "require an existing key without creating one")
	importPrivate := fs.String("import-private", "", "legacy WireGuard private key to preserve")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if pair, err := wgnet.LoadKeyPair(*stateDir); err == nil {
		fmt.Fprintln(stdout, pair.PublicKey)
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if *check {
		if *importPrivate != "" {
			if raw, readErr := os.ReadFile(*importPrivate); readErr == nil {
				pair, pairErr := wgnet.KeyPairFromPrivate(string(raw))
				if pairErr != nil {
					return pairErr
				}
				fmt.Fprintln(stdout, pair.PublicKey)
				return nil
			}
		}
		return errors.New("no existing network key; a check run cannot create one")
	}
	var pair wgnet.KeyPair
	var err error
	if *importPrivate != "" {
		raw, readErr := os.ReadFile(*importPrivate)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		if readErr == nil {
			pair, err = wgnet.KeyPairFromPrivate(string(raw))
		} else {
			pair, err = wgnet.GenerateKeyPair()
		}
	} else {
		pair, err = wgnet.GenerateKeyPair()
	}
	if err != nil {
		return err
	}
	if err := wgnet.SaveKeyPair(*stateDir, pair); err != nil {
		return err
	}
	fmt.Fprintln(stdout, pair.PublicKey)
	return nil
}

func publicKey(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("public-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state", "/var/lib/parallaxd/network", "private state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pair, err := wgnet.LoadKeyPair(*stateDir)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, pair.PublicKey)
	return nil
}

func reconcile(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state", "/var/lib/parallaxd/network", "private state directory")
	topologyPath := fs.String("topology", "", "declarative topology JSON")
	check := fs.Bool("check", false, "validate and report change without writing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *topologyPath == "" {
		return errors.New("--topology is required")
	}
	var topology wgnet.Topology
	if err := wgnet.LoadJSON(*topologyPath, &topology); err != nil {
		return err
	}
	var current *wgnet.State
	if s, err := wgnet.LoadState(*stateDir); err == nil {
		current = &s
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	next, changed, err := wgnet.Reconcile(current, topology)
	if err != nil {
		return err
	}
	if current == nil {
		pair, err := wgnet.LoadKeyPair(*stateDir)
		if err != nil {
			return err
		}
		next.PrivateKey, next.PublicKey = pair.PrivateKey, pair.PublicKey
		next, _, err = wgnet.Reconcile(&next, topology)
		changed = true
		if err != nil {
			return err
		}
	}
	if changed && !*check {
		if err := wgnet.SaveState(*stateDir, next); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "{\"changed\":%t,\"interface\":%q}\n", changed, next.Interface)
	return nil
}

func hubInit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("hub-init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state", "./parallaxd-network", "private state directory")
	name := fs.String("name", "coordinator", "node name")
	iface := fs.String("interface", "wg-parallaxd", "WireGuard interface")
	address := fs.String("address", "10.77.0.1/24", "hub overlay address/prefix")
	overlay := fs.String("overlay", "10.77.0.0/24", "routed overlay prefix")
	endpoint := fs.String("endpoint", "", "public hub endpoint, host:port")
	port := fs.Int("listen-port", 51821, "hub UDP listen port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *endpoint == "" {
		return errors.New("--endpoint is required")
	}
	s, invitation, err := wgnet.InitHub(wgnet.InitHubOptions{Name: *name, Interface: *iface,
		Address: *address, Overlay: *overlay, Endpoint: *endpoint, ListenPort: *port})
	if err != nil {
		return err
	}
	if err := refuseExisting(*stateDir); err != nil {
		return err
	}
	if err := wgnet.SaveState(*stateDir, s); err != nil {
		return err
	}
	path := filepath.Join(*stateDir, "invitation.json")
	if err := wgnet.SaveJSON(path, invitation, 0644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Created private hub state in %s\nShare only %s\n", *stateDir, path)
	return nil
}

func peerInit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("peer-init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state", "./parallaxd-network", "private state directory")
	invitationPath := fs.String("invitation", "", "hub invitation JSON")
	name := fs.String("name", "", "unique peer name")
	address := fs.String("address", "", "peer overlay address/prefix")
	endpoint := fs.String("endpoint", "", "optional public peer endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *invitationPath == "" || *name == "" || *address == "" {
		return errors.New("--invitation, --name, and --address are required")
	}
	var invitation wgnet.Invitation
	if err := wgnet.LoadJSON(*invitationPath, &invitation); err != nil {
		return fmt.Errorf("read invitation: %w", err)
	}
	s, request, err := wgnet.InitPeer(wgnet.InitPeerOptions{Name: *name, Address: *address,
		Endpoint: *endpoint, Invitation: invitation})
	if err != nil {
		return err
	}
	if err := refuseExisting(*stateDir); err != nil {
		return err
	}
	if err := wgnet.SaveState(*stateDir, s); err != nil {
		return err
	}
	path := filepath.Join(*stateDir, "enrollment.json")
	if err := wgnet.SaveJSON(path, request, 0644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Created private peer state in %s\nReturn only %s to the hub operator\n", *stateDir, path)
	return nil
}

func authorize(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("authorize", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state", "./parallaxd-network", "hub state directory")
	requestPath := fs.String("request", "", "peer enrollment request JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *requestPath == "" {
		return errors.New("--request is required")
	}
	s, err := wgnet.LoadState(*stateDir)
	if err != nil {
		return err
	}
	var request wgnet.Request
	if err := wgnet.LoadJSON(*requestPath, &request); err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	if err := s.Authorize(request); err != nil {
		return err
	}
	if err := wgnet.SaveState(*stateDir, s); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Authorized %s at %s; render and install the updated hub configuration\n", request.Name, request.Address)
	return nil
}

func render(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state", "./parallaxd-network", "private state directory")
	output := fs.String("output", "", "configuration output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *output == "" {
		return errors.New("--output is required; configuration contains a private key")
	}
	s, err := wgnet.LoadState(*stateDir)
	if err != nil {
		return err
	}
	config, err := s.Config()
	if err != nil {
		return err
	}
	if err := wgnet.WriteConfig(*output, config); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Wrote %s for interface %s\n", *output, s.Interface)
	return nil
}

func install(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state", "/var/lib/parallaxd/network", "private state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("install must run as root")
	}
	s, err := wgnet.LoadState(*stateDir)
	if err != nil {
		return err
	}
	config, err := s.Config()
	if err != nil {
		return err
	}
	tmpDir, err := os.MkdirTemp("", "parallaxd-network-validate-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	candidate := filepath.Join(tmpDir, s.Interface+".conf")
	if err := wgnet.WriteConfig(candidate, config); err != nil {
		return err
	}
	if output, err := exec.Command("wg-quick", "strip", candidate).CombinedOutput(); err != nil {
		return fmt.Errorf("WireGuard rejected configuration: %s: %w", strings.TrimSpace(string(output)), err)
	}
	destination := filepath.Join("/etc/wireguard", s.Interface+".conf")
	existing, readErr := os.ReadFile(destination)
	changed := readErr != nil || string(existing) != config
	if changed {
		if err := wgnet.WriteConfig(destination, config); err != nil {
			return err
		}
	}
	if s.Role == wgnet.RoleHub && s.Forward {
		forwarding := "net.ipv4.ip_forward = 1\n"
		if strings.Contains(s.Overlay, ":") {
			forwarding = "net.ipv6.conf.all.forwarding = 1\n"
		}
		sysctlPath := "/etc/sysctl.d/90-parallaxd-network.conf"
		if err := wgnet.WritePublicConfig(sysctlPath, forwarding); err != nil {
			return err
		}
		if output, err := exec.Command("sysctl", "-p", sysctlPath).CombinedOutput(); err != nil {
			return fmt.Errorf("enable overlay forwarding: %s: %w", strings.TrimSpace(string(output)), err)
		}
	}
	unit := "wg-quick@" + s.Interface + ".service"
	if output, err := exec.Command("systemctl", "enable", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("enable %s: %s: %w", unit, strings.TrimSpace(string(output)), err)
	}
	if changed {
		if output, err := exec.Command("systemctl", "restart", unit).CombinedOutput(); err != nil {
			return fmt.Errorf("restart %s: %s: %w", unit, strings.TrimSpace(string(output)), err)
		}
	} else if err := exec.Command("systemctl", "is-active", "--quiet", unit).Run(); err != nil {
		if output, err := exec.Command("systemctl", "start", unit).CombinedOutput(); err != nil {
			return fmt.Errorf("start %s: %s: %w", unit, strings.TrimSpace(string(output)), err)
		}
		changed = true
	}
	fmt.Fprintf(stdout, "{\"changed\":%t,\"installed\":%q,\"unit\":%q}\n", changed, destination, unit)
	return nil
}

func refuseExisting(dir string) error {
	_, err := os.Stat(filepath.Join(dir, "state.json"))
	if err == nil {
		return errors.New("state already exists; refusing to replace private keys")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
