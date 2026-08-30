// Command parallaxd-mcp exposes an authenticated Parallaxd coordinator as a
// local stdio MCP server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/parallaxd/internal/mcpserver"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "parallaxd-mcp:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("parallaxd-mcp", flag.ContinueOnError)
	coordinator := fs.String("coordinator", "", "coordinator base URL")
	tokenFile := fs.String("token-file", "", "file containing a dedicated coordinator API token")
	actor := fs.String("actor", "mcp", "audit actor used with legacy operator tokens")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println("parallaxd-mcp", version)
		return nil
	}
	if strings.TrimSpace(*coordinator) == "" {
		return errors.New("-coordinator is required")
	}
	if strings.TrimSpace(*tokenFile) == "" {
		return errors.New("-token-file is required")
	}
	token, err := readTokenFile(*tokenFile)
	if err != nil {
		return err
	}
	client := mcpserver.Client{BaseURL: *coordinator, Token: token, Actor: *actor}
	if err := client.Validate(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return mcpkit.RunStdio(ctx, mcpserver.New(client, version))
}

func readTokenFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open token file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat token file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("token file must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("token file must not be accessible by group or other users (use mode 0600)")
	}
	const maxTokenBytes = 8 << 10
	raw, err := io.ReadAll(io.LimitReader(file, maxTokenBytes+1))
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}
	if len(raw) > maxTokenBytes {
		return "", errors.New("token file exceeds 8 KiB")
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("token file is empty")
	}
	return token, nil
}
