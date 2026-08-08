package coordinator

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

const (
	defaultHistoryRetention   = 30 * 24 * time.Hour
	defaultHistoryMaxPerCheck = 10000
	historyCompactEvery       = 1000
)

// Observation is one prober's accepted result, before quorum folds multiple
// vantages into a verdict.
type Observation struct {
	ID         string       `json:"id"`
	Check      string       `json:"check"`
	Kind       check.Kind   `json:"kind"`
	Target     string       `json:"target"`
	Prober     string       `json:"prober"`
	Provider   string       `json:"provider,omitempty"`
	Status     check.Status `json:"status"`
	Verdict    check.Status `json:"verdict,omitempty"`
	ObservedAt time.Time    `json:"observed_at"`
	ReceivedAt time.Time    `json:"received_at"`
	LatencyMS  int64        `json:"latency_ms,omitempty"`
	Detail     string       `json:"detail,omitempty"`
	Source     string       `json:"source"`
	Suppressed bool         `json:"suppressed,omitempty"`

	DNSAnswers    []string  `json:"dns_answers,omitempty"`
	TLSCommonName string    `json:"tls_common_name,omitempty"`
	TLSExpiresAt  time.Time `json:"tls_expires_at,omitzero"`
}

type HistorySummary struct {
	Check            string     `json:"check"`
	Kind             check.Kind `json:"kind"`
	Samples          int        `json:"samples"`
	Up               int        `json:"up"`
	Down             int        `json:"down"`
	Unknown          int        `json:"unknown"`
	Suppressed       int        `json:"suppressed"`
	Corroborations   int        `json:"corroborations"`
	Availability     float64    `json:"availability"`
	AverageLatencyMS int64      `json:"average_latency_ms,omitempty"`
	P95LatencyMS     int64      `json:"p95_latency_ms,omitempty"`
	FirstObservedAt  time.Time  `json:"first_observed_at,omitzero"`
	LastObservedAt   time.Time  `json:"last_observed_at,omitzero"`
	TLSExpiresAt     time.Time  `json:"tls_expires_at,omitzero"`
	TLSDaysRemaining int        `json:"tls_days_remaining"`
	DNSAnswers       []string   `json:"dns_answers,omitempty"`
}

func (c *Coordinator) historyRetention() time.Duration {
	if c.cfg.HistoryRetention > 0 {
		return c.cfg.HistoryRetention
	}
	return defaultHistoryRetention
}

func (c *Coordinator) historyMaxPerCheck() int {
	if c.cfg.HistoryMaxPerCheck > 0 {
		return c.cfg.HistoryMaxPerCheck
	}
	return defaultHistoryMaxPerCheck
}

func (c *Coordinator) recordObservation(chk check.Check, result check.Result, source string, suppressed bool, verdict check.Status) {
	observation := Observation{
		Check: chk.Name, Kind: chk.Kind, Target: chk.Target, Prober: result.Prober,
		Provider: result.Provider, Status: result.Status, ObservedAt: result.At.UTC(),
		ReceivedAt: c.now().UTC(), LatencyMS: result.Latency.Milliseconds(),
		Detail: result.Detail, Source: source, Suppressed: suppressed, Verdict: verdict,
	}
	observation.addProtocolMetadata()
	observation.ensureID()
	c.historyMu.Lock()
	c.appendHistoryLocked(observation)
	if c.cfg.HistoryFile != "" {
		if err := appendObservation(c.cfg.HistoryFile, observation); err != nil {
			c.log.Error("appending observation history", "check", observation.Check, "err", err)
			c.recordHistoryWrite(err)
		} else {
			c.recordHistoryWrite(nil)
			c.historyAppends++
			if c.historyAppends >= historyCompactEvery {
				if err := c.compactHistoryLocked(); err != nil {
					c.log.Error("compacting observation history", "err", err)
					c.recordHistoryWrite(err)
				} else {
					c.historyAppends = 0
				}
			}
		}
	}
	c.historyMu.Unlock()
}

func (o *Observation) ensureID() {
	if o.ID != "" {
		return
	}
	raw, _ := json.Marshal(struct {
		Check                  string
		Prober                 string
		ObservedAt, ReceivedAt time.Time
		Source                 string
	}{o.Check, o.Prober, o.ObservedAt, o.ReceivedAt, o.Source})
	sum := sha256.Sum256(raw)
	o.ID = fmt.Sprintf("%x", sum[:16])
}

func (c *Coordinator) recordHistoryWrite(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.diagnostics.History.WriteFailures++
		c.diagnostics.History.LastError = err.Error()
		return
	}
	c.diagnostics.History.LastWrite = c.now().UTC()
	c.diagnostics.History.LastError = ""
}

func (o *Observation) addProtocolMetadata() {
	switch o.Kind {
	case check.KindDNS:
		if o.Status == check.StatusUp && o.Detail != "" {
			o.DNSAnswers = strings.Split(o.Detail, "\n")
		}
	case check.KindTLS:
		parts := strings.Split(o.Detail, "; ")
		if len(parts) >= 2 {
			o.TLSCommonName = parts[1]
		}
		for _, part := range parts {
			if strings.HasPrefix(part, "expires ") {
				o.TLSExpiresAt, _ = time.Parse(time.RFC3339, strings.TrimPrefix(part, "expires "))
			}
		}
	}
}

func appendObservation(path string, observation Observation) error {
	return appendObservations(path, []Observation{observation})
}

func appendObservations(path string, observations []Observation) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	for _, observation := range observations {
		if err = encoder.Encode(observation); err != nil {
			break
		}
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = syncDirectory(filepath.Dir(path))
	}
	return err
}

func (c *Coordinator) appendHistoryLocked(observation Observation) {
	items := c.history[observation.Check]
	insertAt := sort.Search(len(items), func(i int) bool {
		return items[i].ReceivedAt.After(observation.ReceivedAt)
	})
	items = append(items, Observation{})
	copy(items[insertAt+1:], items[insertAt:])
	items[insertAt] = observation
	cutoff := c.now().UTC().Add(-c.historyRetention())
	first := sort.Search(len(items), func(i int) bool { return !items[i].ReceivedAt.Before(cutoff) })
	items = items[first:]
	if max := c.historyMaxPerCheck(); len(items) > max {
		items = items[len(items)-max:]
	}
	c.history[observation.Check] = append([]Observation(nil), items...)
}

func (c *Coordinator) loadHistory() error {
	if c.cfg.HistoryFile == "" {
		return nil
	}
	file, err := os.Open(c.cfg.HistoryFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read history file: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	dropped := false
	for scanner.Scan() {
		var observation Observation
		if err := json.Unmarshal(scanner.Bytes(), &observation); err != nil {
			c.log.Warn("skipping malformed observation history line", "err", err)
			dropped = true
			continue
		}
		observation.ensureID()
		if _, ok := c.checks[observation.Check]; !ok || observation.ReceivedAt.Before(c.now().UTC().Add(-c.historyRetention())) {
			dropped = true
			continue
		}
		before := len(c.history[observation.Check])
		c.appendHistoryLocked(observation)
		if before == c.historyMaxPerCheck() {
			dropped = true
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan history file: %w", err)
	}
	if dropped {
		return c.compactHistoryLocked()
	}
	return nil
}

func (c *Coordinator) compactHistoryLocked() error {
	if c.cfg.HistoryFile == "" {
		return nil
	}
	dir := filepath.Dir(c.cfg.HistoryFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".parallaxd-history-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	names := make([]string, 0, len(c.history))
	for name := range c.history {
		names = append(names, name)
	}
	sort.Strings(names)
	encoder := json.NewEncoder(tmp)
	for _, name := range names {
		for _, observation := range c.history[name] {
			if err := encoder.Encode(observation); err != nil {
				tmp.Close()
				return err
			}
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, c.cfg.HistoryFile); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func (c *Coordinator) History(checkName string, since time.Time, limit int) []Observation {
	c.historyMu.Lock()
	defer c.historyMu.Unlock()
	var out []Observation
	cutoff := c.now().UTC().Add(-c.historyRetention())
	if since.IsZero() || since.Before(cutoff) {
		since = cutoff
	}
	appendItems := func(items []Observation) {
		for _, observation := range items {
			if !observation.ReceivedAt.Before(since) {
				out = append(out, observation)
			}
		}
	}
	if checkName != "" {
		appendItems(c.history[checkName])
	} else {
		for _, items := range c.history {
			appendItems(items)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ReceivedAt.Before(out[j].ReceivedAt) })
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return append([]Observation{}, out...)
}

func (c *Coordinator) HistorySummaries() []HistorySummary {
	now := c.now().UTC()
	c.historyMu.Lock()
	defer c.historyMu.Unlock()
	out := make([]HistorySummary, 0, len(c.checks))
	for name, chk := range c.checks {
		items := c.history[name]
		summary := HistorySummary{Check: name, Kind: chk.Kind}
		var latencies []int64
		var considered []Observation
		cutoff := now.Add(-c.historyRetention())
		for _, observation := range items {
			if observation.ReceivedAt.Before(cutoff) {
				continue
			}
			summary.Samples++
			considered = append(considered, observation)
			if observation.Source == "corroboration" {
				summary.Corroborations++
				continue
			}
			if observation.Suppressed {
				summary.Suppressed++
				continue
			}
			verdict := observation.Verdict
			if verdict == "" {
				verdict = observation.Status
			}
			switch verdict {
			case check.StatusUp:
				summary.Up++
			case check.StatusDown:
				summary.Down++
			default:
				summary.Unknown++
			}
			if verdict == check.StatusUp && observation.Status == check.StatusUp && observation.LatencyMS >= 0 {
				latencies = append(latencies, observation.LatencyMS)
			}
			if !observation.TLSExpiresAt.IsZero() {
				summary.TLSExpiresAt = observation.TLSExpiresAt
				summary.TLSDaysRemaining = int(observation.TLSExpiresAt.Sub(now).Hours() / 24)
			}
			if len(observation.DNSAnswers) > 0 {
				summary.DNSAnswers = append([]string(nil), observation.DNSAnswers...)
			}
		}
		if len(considered) > 0 {
			summary.FirstObservedAt = considered[0].ReceivedAt
			summary.LastObservedAt = considered[len(considered)-1].ReceivedAt
		}
		decided := summary.Up + summary.Down
		if decided > 0 {
			summary.Availability = float64(summary.Up) / float64(decided)
		}
		if len(latencies) > 0 {
			sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
			var total int64
			for _, latency := range latencies {
				total += latency
			}
			summary.AverageLatencyMS = total / int64(len(latencies))
			index := (len(latencies)*95+99)/100 - 1
			summary.P95LatencyMS = latencies[index]
		}
		out = append(out, summary)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Check < out[j].Check })
	return out
}

func (c *Coordinator) handleHistory(w http.ResponseWriter, r *http.Request) {
	checkName := r.URL.Query().Get("check")
	if checkName != "" {
		if _, ok := c.checks[checkName]; !ok {
			http.Error(w, "unknown check", http.StatusBadRequest)
			return
		}
	}
	var since time.Time
	if raw := r.URL.Query().Get("since"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			http.Error(w, "since must be RFC3339", http.StatusBadRequest)
			return
		}
		since = parsed
	}
	limit := 1000
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 10000 {
			http.Error(w, "limit must be 1..10000", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	writeJSON(w, c.History(checkName, since, limit))
}

func (c *Coordinator) handleHistorySummary(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, c.HistorySummaries())
}
