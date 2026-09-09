package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/kilo666mj/parallaxd/internal/coordinator"
)

// verifyBackup uses the normal restore path, which may compact history or
// bootstrap authentication. Only disposable copies are passed to that path.
// os.Root prevents a missing backup file or symlink from falling back to live
// host secrets/state. No workers, HTTP handlers or listeners are started.
func verifyBackup(backupRoot, configPath string, log *slog.Logger) (err error) {
	root, err := os.OpenRoot(backupRoot)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	tmp, err := os.MkdirTemp("", "parallaxd-restore-*")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(tmp)) }()
	copyFile := func(path string) (string, error) {
		if !filepath.IsAbs(path) {
			return "", errors.New("backup references must be absolute paths")
		}
		rel := strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator))
		if !filepath.IsLocal(rel) {
			return "", errors.New("invalid backup reference")
		}
		source, err := root.Open(rel)
		if err != nil {
			return "", fmt.Errorf("open backed-up %s: %w", path, err)
		}
		defer func() { _ = source.Close() }()
		info, err := source.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return "", fmt.Errorf("backup reference %s is not a regular file", path)
		}
		dest := filepath.Join(tmp, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			return "", err
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return "", err
		}
		_, copyErr := io.Copy(out, source)
		if err := errors.Join(copyErr, out.Close()); err != nil {
			return "", err
		}
		return dest, nil
	}
	path, err := copyFile(configPath)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if cfg.StateFile == "" || cfg.HistoryFile == "" {
		return errors.New("backup verification requires state_file and history_file")
	}
	copied := map[string]string{configPath: path}
	references := []*string{&cfg.KeyFile, &cfg.OperatorTokenFile,
		&cfg.BootstrapPasswordFile, &cfg.HA.ReplicationTokenFile,
		&cfg.OIDC.ClientSecretFile, &cfg.StateFile, &cfg.HistoryFile}
	for i := range cfg.Prometheus {
		references = append(references, &cfg.Prometheus[i].BearerTokenFile,
			&cfg.Prometheus[i].CAFile, &cfg.Prometheus[i].CertFile, &cfg.Prometheus[i].KeyFile)
	}
	for _, ref := range references {
		if *ref == "" {
			continue
		}
		if existing, ok := copied[*ref]; ok {
			*ref = existing
			continue
		}
		p, err := copyFile(*ref)
		if err != nil {
			return err
		}
		copied[*ref], *ref = p, p
	}
	// Startup deliberately tolerates malformed journal lines. A backup
	// assurance check must report corruption instead of silently losing them.
	if err := verifyJournal(cfg.HistoryFile); err != nil {
		return err
	}
	_, _, err = prepareConfig(cfg, log, true)
	return err
}

func verifyJournal(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	for scanner.Scan() {
		line++
		var observation coordinator.Observation
		if err := json.Unmarshal(scanner.Bytes(), &observation); err != nil {
			return fmt.Errorf("malformed observation at line %d", line)
		}
		if observation.Check == "" || observation.ReceivedAt.IsZero() {
			return fmt.Errorf("incomplete observation at line %d", line)
		}
	}
	return scanner.Err()
}
