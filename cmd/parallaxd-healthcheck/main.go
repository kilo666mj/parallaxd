// Command parallaxd-healthcheck checks a local Parallaxd HTTP endpoint.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: parallaxd-healthcheck URL")
		os.Exit(2)
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// The body has been read; a close failure now is not evidence about
	// anything this code reports.
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		fmt.Fprintln(os.Stderr, resp.Status)
		os.Exit(1)
	}
}
