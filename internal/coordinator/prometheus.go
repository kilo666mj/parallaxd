package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultPrometheusTimeout = 8 * time.Second
	hostMetricsCacheTTL      = 15 * time.Second
	maxPrometheusResponse    = 2 << 20
	maxPrometheusHosts       = 1000
)

// PrometheusSource is one read-only metrics data source. MatchLabels must
// identify the node-exporter scrape job (for example {"job":"node"}); this
// prevents an empty configuration from accidentally exposing every target in
// a shared Prometheus server.
type PrometheusSource struct {
	Name          string
	URL           string
	MatchLabels   map[string]string
	AllowInsecure bool
	Client        *http.Client
}

type prometheusRuntime struct {
	name        string
	baseURL     *url.URL
	matchLabels map[string]string
	client      *http.Client
	cache       *prometheusCache
}

type prometheusCache struct {
	mu    sync.Mutex
	at    time.Time
	hosts []HostMetrics
	err   error
}

// HostMetrics is a deliberately small, normalized view of node_exporter data.
// Missing measurements are omitted rather than interpreted as healthy or
// unhealthy; Prometheus remains authoritative for metric alerting.
type HostMetrics struct {
	Instance           string   `json:"instance"`
	Hostname           string   `json:"hostname,omitempty"`
	Up                 *bool    `json:"up,omitempty"`
	CPUUsedPercent     *float64 `json:"cpu_used_percent,omitempty"`
	MemoryUsedPercent  *float64 `json:"memory_used_percent,omitempty"`
	FilesystemUsedPeak *float64 `json:"filesystem_used_peak_percent,omitempty"`
	Load1              *float64 `json:"load1,omitempty"`
	UptimeSeconds      *float64 `json:"uptime_seconds,omitempty"`
}

type HostMetricsSource struct {
	Name  string        `json:"name"`
	Hosts []HostMetrics `json:"hosts"`
	Error string        `json:"error,omitempty"`
}

func preparePrometheusSources(sources []PrometheusSource) ([]prometheusRuntime, error) {
	seen := make(map[string]bool, len(sources))
	out := make([]prometheusRuntime, 0, len(sources))
	for _, source := range sources {
		name := strings.TrimSpace(source.Name)
		if name == "" || !validIdentifier(name) {
			return nil, fmt.Errorf("prometheus source name %q must be a 1-64 character identifier", source.Name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate prometheus source name %q", name)
		}
		seen[name] = true
		base, err := url.Parse(source.URL)
		if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") {
			return nil, fmt.Errorf("prometheus source %q needs an absolute HTTP(S) URL", name)
		}
		if base.User != nil || base.RawQuery != "" || base.Fragment != "" {
			return nil, fmt.Errorf("prometheus source %q URL may not contain userinfo, a query, or a fragment", name)
		}
		if base.Scheme == "http" && !source.AllowInsecure {
			return nil, fmt.Errorf("prometheus source %q uses HTTP; set allow_insecure only for a protected local or private transport", name)
		}
		if len(source.MatchLabels) == 0 {
			return nil, fmt.Errorf("prometheus source %q needs match_labels identifying its node-exporter targets", name)
		}
		labels := make(map[string]string, len(source.MatchLabels))
		for key, value := range source.MatchLabels {
			if !validPrometheusLabelName(key) || strings.TrimSpace(value) == "" {
				return nil, fmt.Errorf("prometheus source %q has invalid match label %q", name, key)
			}
			labels[key] = value
		}
		client := source.Client
		if client == nil {
			client = &http.Client{Timeout: defaultPrometheusTimeout}
		}
		// Fixed data sources do not need redirects. Refusing them also prevents a
		// bearer-authenticated client from being steered to another origin.
		clientCopy := *client
		clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &clientCopy
		base.Path = strings.TrimRight(base.Path, "/")
		out = append(out, prometheusRuntime{name: name, baseURL: base, matchLabels: labels, client: client, cache: &prometheusCache{}})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for i, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9' && i > 0) || (i > 0 && (r == '.' || r == '_' || r == '-')) {
			continue
		}
		return false
	}
	return true
}

func validPrometheusLabelName(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

func (p prometheusRuntime) selector(extra ...string) string {
	labels := make([]string, 0, len(p.matchLabels)+len(extra))
	for key, value := range p.matchLabels {
		labels = append(labels, key+"="+strconv.Quote(value))
	}
	labels = append(labels, extra...)
	sort.Strings(labels)
	return "{" + strings.Join(labels, ",") + "}"
}

type prometheusResponse struct {
	Status    string `json:"status"`
	ErrorType string `json:"errorType"`
	Error     string `json:"error"`
	Data      struct {
		ResultType string             `json:"resultType"`
		Result     []prometheusSample `json:"result"`
	} `json:"data"`
}

type prometheusSample struct {
	Metric map[string]string `json:"metric"`
	Value  []json.RawMessage `json:"value"`
}

func (p prometheusRuntime) query(ctx context.Context, query string) (map[string]prometheusSample, error) {
	endpoint := *p.baseURL
	endpoint.Path += "/api/v1/query"
	values := endpoint.Query()
	values.Set("query", query)
	endpoint.RawQuery = values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("query returned HTTP %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, maxPrometheusResponse+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read query response: %w", err)
	}
	if len(raw) > maxPrometheusResponse {
		return nil, errors.New("query response exceeds 2 MiB limit")
	}
	var decoded prometheusResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("decode query response: %w", err)
	}
	if decoded.Status != "success" {
		return nil, fmt.Errorf("prometheus %s: %s", decoded.ErrorType, decoded.Error)
	}
	if decoded.Data.ResultType != "vector" {
		return nil, fmt.Errorf("unexpected result type %q", decoded.Data.ResultType)
	}
	if len(decoded.Data.Result) > maxPrometheusHosts {
		return nil, fmt.Errorf("query returned more than %d series", maxPrometheusHosts)
	}
	out := make(map[string]prometheusSample, len(decoded.Data.Result))
	for _, sample := range decoded.Data.Result {
		instance := sample.Metric["instance"]
		if instance != "" {
			out[instance] = sample
		}
	}
	return out, nil
}

func sampleFloat(sample prometheusSample) (*float64, bool) {
	if len(sample.Value) != 2 {
		return nil, false
	}
	var value string
	if err := json.Unmarshal(sample.Value[1], &value); err != nil {
		return nil, false
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return nil, false
	}
	return &parsed, true
}

func clampPercent(value *float64) *float64 {
	if value == nil {
		return nil
	}
	clamped := max(0, min(100, *value))
	return &clamped
}

func (p prometheusRuntime) hosts(ctx context.Context) ([]HostMetrics, error) {
	selector := p.selector()
	filesystemSelector := p.selector(`fstype!~"autofs|binfmt_misc|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|overlay|proc|procfs|pstore|securityfs|squashfs|sysfs|tmpfs|tracefs"`, `mountpoint!~"/run($|/)|/var/lib/(docker|containers)($|/)"`)
	queries := []struct {
		name string
		expr string
	}{
		{"up", "max by(instance) (up" + selector + ")"},
		{"identity", "node_uname_info" + selector},
		{"cpu", "100 * (1 - avg by(instance) (rate(node_cpu_seconds_total" + p.selector(`mode="idle"`) + "[5m])))"},
		{"memory", "100 * (1 - node_memory_MemAvailable_bytes" + selector + " / node_memory_MemTotal_bytes" + selector + ")"},
		{"filesystem", "max by(instance) (100 * (1 - node_filesystem_avail_bytes" + filesystemSelector + " / node_filesystem_size_bytes" + filesystemSelector + "))"},
		{"load", "node_load1" + selector},
		{"uptime", "time() - node_boot_time_seconds" + selector},
	}
	results := make(map[string]map[string]prometheusSample, len(queries))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for _, item := range queries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := p.query(ctx, item.expr)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("%s: %w", item.name, err)
				}
				return
			}
			results[item.name] = result
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	instances := map[string]bool{}
	for _, result := range results {
		for instance := range result {
			instances[instance] = true
		}
	}
	if len(instances) > maxPrometheusHosts {
		return nil, fmt.Errorf("source contains more than %d hosts", maxPrometheusHosts)
	}
	hosts := make([]HostMetrics, 0, len(instances))
	for instance := range instances {
		host := HostMetrics{Instance: instance}
		if sample, ok := results["identity"][instance]; ok {
			host.Hostname = sample.Metric["nodename"]
		}
		if value, ok := sampleFloat(results["up"][instance]); ok {
			up := *value == 1
			host.Up = &up
		}
		if value, ok := sampleFloat(results["cpu"][instance]); ok {
			host.CPUUsedPercent = clampPercent(value)
		}
		if value, ok := sampleFloat(results["memory"][instance]); ok {
			host.MemoryUsedPercent = clampPercent(value)
		}
		if value, ok := sampleFloat(results["filesystem"][instance]); ok {
			host.FilesystemUsedPeak = clampPercent(value)
		}
		if value, ok := sampleFloat(results["load"][instance]); ok {
			host.Load1 = value
		}
		if value, ok := sampleFloat(results["uptime"][instance]); ok {
			host.UptimeSeconds = value
		}
		hosts = append(hosts, host)
	}
	sort.Slice(hosts, func(i, j int) bool {
		left, right := hosts[i].Hostname, hosts[j].Hostname
		if left == "" {
			left = hosts[i].Instance
		}
		if right == "" {
			right = hosts[j].Instance
		}
		return left < right
	})
	return hosts, nil
}

func (p prometheusRuntime) cachedHosts(ctx context.Context) ([]HostMetrics, error) {
	p.cache.mu.Lock()
	defer p.cache.mu.Unlock()
	if !p.cache.at.IsZero() && time.Since(p.cache.at) < hostMetricsCacheTTL {
		return append([]HostMetrics(nil), p.cache.hosts...), p.cache.err
	}
	hosts, err := p.hosts(ctx)
	if ctx.Err() != nil {
		return nil, err
	}
	p.cache.at = time.Now()
	p.cache.hosts = append([]HostMetrics(nil), hosts...)
	p.cache.err = err
	return hosts, err
}

func (c *Coordinator) handleHostMetrics(w http.ResponseWriter, r *http.Request) {
	if len(c.prometheus) == 0 {
		writeJSON(w, []HostMetricsSource{})
		return
	}
	results := make([]HostMetricsSource, len(c.prometheus))
	var wg sync.WaitGroup
	for index, source := range c.prometheus {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[index].Name = source.name
			hosts, err := source.cachedHosts(r.Context())
			if err != nil {
				c.log.Warn("prometheus host metrics unavailable", "source", source.name, "err", err)
				results[index].Error = "metrics source unavailable"
				results[index].Hosts = []HostMetrics{}
				return
			}
			results[index].Hosts = hosts
		}()
	}
	wg.Wait()
	writeJSON(w, results)
}
