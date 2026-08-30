package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"
)

const maxResponseBytes = 16 << 20

// Client talks to the authenticated operator API. Keeping MCP behind this API
// preserves the coordinator's authorization, validation, revision, and audit
// behavior instead of creating a second management path.
type Client struct {
	BaseURL string
	Token   string
	Actor   string
	HTTP    *http.Client
}

type handlerTransport struct {
	handler http.Handler
}

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	t.handler.ServeHTTP(recorder, req)
	return recorder.Result(), nil
}

func (c Client) Validate() error {
	u, err := url.Parse(strings.TrimSpace(c.BaseURL))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("coordinator must be an absolute http or https URL")
	}
	if strings.TrimSpace(c.Token) == "" {
		return fmt.Errorf("coordinator API token is required")
	}
	return nil
}

func (c Client) Get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

func (c Client) Post(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

func (c Client) Put(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPut, path, body, out)
}

func (c Client) Delete(ctx context.Context, path string, body any) error {
	return c.do(ctx, http.MethodDelete, path, body, nil)
}

func (c Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, reader)
	if err != nil {
		return fmt.Errorf("build coordinator request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if actor := strings.TrimSpace(c.Actor); actor != "" {
		req.Header.Set("X-Parallaxd-Actor", actor)
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("call coordinator: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("coordinator returned %s: %s", resp.Status, strings.TrimSpace(string(message)))
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
		return fmt.Errorf("decode coordinator response: %w", err)
	}
	return nil
}
