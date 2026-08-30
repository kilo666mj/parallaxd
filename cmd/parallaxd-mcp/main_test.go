package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("  secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := readTokenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if token != "secret-token" {
		t.Fatalf("token = %q", token)
	}

	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readTokenFile(path); err == nil || !strings.Contains(err.Error(), "mode 0600") {
		t.Fatalf("unsafe permissions error = %v", err)
	}
}

func TestReadTokenFileRejectsInvalidContent(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
		want    string
	}{
		{name: "empty", content: " \n", want: "empty"},
		{name: "oversized", content: strings.Repeat("x", (8<<10)+1), want: "exceeds"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readTokenFile(path); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}
