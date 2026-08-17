package probe

import (
	"crypto/x509"
	"fmt"
	"os"
)

// rootsForCheck augments the host (or caller-provided) trust store with the
// monitor's local CA file. The file contents never enter coordinator traffic;
// every prober reads its own copy, so CA rotation needs no catalogue change.
func rootsForCheck(path string, base *x509.CertPool) (*x509.CertPool, error) {
	if path == "" {
		return base, nil
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
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ca_file %q: %w", path, err)
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca_file %q contains no certificates", path)
	}
	return roots, nil
}
