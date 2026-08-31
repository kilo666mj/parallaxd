package probe

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const customCARoot = "/etc/parallaxd/ca"

// rootsForCheck augments the host (or caller-provided) trust store with the
// monitor's local CA file. The file contents never enter coordinator traffic;
// every prober reads its own copy, so CA rotation needs no catalogue change.
func rootsForCheck(path string, base *x509.CertPool) (*x509.CertPool, error) {
	return rootsForCheckIn(path, base, customCARoot)
}

func rootsForCheckIn(path string, base *x509.CertPool, allowedRoot string) (*x509.CertPool, error) {
	if path == "" {
		return base, nil
	}
	root, err := filepath.EvalSymlinks(allowedRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve ca_file root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("resolve ca_file %q: %w", path, err)
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("ca_file %q is outside %s", path, allowedRoot)
	}
	var roots *x509.CertPool
	if base != nil {
		roots = base.Clone()
	} else {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system CA pool: %w", err)
		}
	}
	pem, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("read ca_file %q: %w", path, err)
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca_file %q contains no certificates", path)
	}
	return roots, nil
}
