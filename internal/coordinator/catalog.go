package coordinator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

const maxMonitorRevisions = 100

// MonitorSpec is the operator-facing form of a check. Durations are strings
// so the API and dashboard use values such as "1m" rather than nanoseconds.
type MonitorSpec struct {
	Name             string            `json:"name"`
	Enabled          bool              `json:"enabled"`
	Kind             check.Kind        `json:"kind"`
	Target           string            `json:"target"`
	Vantage          check.Vantage     `json:"vantage"`
	Interval         string            `json:"interval"`
	Timeout          string            `json:"timeout"`
	Quorum           check.Quorum      `json:"quorum"`
	Prober           string            `json:"prober,omitempty"`
	Probers          []string          `json:"probers,omitempty"`
	ExpectStatus     []int             `json:"expect_status,omitempty"`
	ExpectBody       string            `json:"expect_body,omitempty"`
	Send             string            `json:"send,omitempty"`
	HTTPMethod       string            `json:"http_method,omitempty"`
	HTTPHeaders      map[string]string `json:"http_headers,omitempty"`
	HTTPBody         string            `json:"http_body,omitempty"`
	ServerName       string            `json:"server_name,omitempty"`
	StartTLS         bool              `json:"start_tls,omitempty"`
	DNSRecord        string            `json:"dns_record,omitempty"`
	DNSServer        string            `json:"dns_server,omitempty"`
	DNSRCode         string            `json:"dns_rcode,omitempty"`
	GRPCService      string            `json:"grpc_service,omitempty"`
	GRPCTLS          bool              `json:"grpc_tls,omitempty"`
	CAFile           string            `json:"ca_file,omitempty"`
	TLSExpiryWarning string            `json:"tls_expiry_warning,omitempty"`
}

type MonitorRevision struct {
	ID      uint64        `json:"id"`
	At      time.Time     `json:"at"`
	Actor   string        `json:"actor"`
	Action  string        `json:"action"`
	Subject string        `json:"subject,omitempty"`
	Catalog []MonitorSpec `json:"catalog"`
}

type MonitorTestResult struct {
	Prober string       `json:"prober"`
	Result check.Result `json:"result,omitzero"`
	Error  string       `json:"error,omitempty"`
}

func monitorFromCheck(chk check.Check) MonitorSpec {
	return MonitorSpec{Name: chk.Name, Enabled: true, Kind: chk.Kind, Target: chk.Target,
		Vantage: chk.Vantage, Interval: chk.Interval.String(), Timeout: chk.Timeout.String(),
		Quorum: chk.Quorum, Prober: chk.Prober, Probers: append([]string(nil), chk.Probers...), ExpectStatus: append([]int(nil), chk.ExpectStatus...),
		ExpectBody: chk.ExpectBody, Send: chk.Send, HTTPMethod: chk.HTTPMethod,
		HTTPHeaders: cloneStrings(chk.HTTPHeaders), HTTPBody: chk.HTTPBody,
		ServerName: chk.ServerName, StartTLS: chk.StartTLS, DNSRecord: chk.DNSRecord,
		DNSServer: chk.DNSServer, DNSRCode: chk.DNSRCode, GRPCService: chk.GRPCService, GRPCTLS: chk.GRPCTLS,
		CAFile:           chk.CAFile,
		TLSExpiryWarning: durationString(chk.TLSExpiryWarning)}
}

func durationString(value time.Duration) string {
	if value == 0 {
		return ""
	}
	return value.String()
}

func (m MonitorSpec) toCheck() (check.Check, error) {
	interval, err := time.ParseDuration(strings.TrimSpace(m.Interval))
	if err != nil {
		return check.Check{}, fmt.Errorf("monitor %q interval: %w", m.Name, err)
	}
	timeout, err := time.ParseDuration(strings.TrimSpace(m.Timeout))
	if err != nil {
		return check.Check{}, fmt.Errorf("monitor %q timeout: %w", m.Name, err)
	}
	var tlsExpiryWarning time.Duration
	if value := strings.TrimSpace(m.TLSExpiryWarning); value != "" {
		tlsExpiryWarning, err = time.ParseDuration(value)
		if err != nil {
			return check.Check{}, fmt.Errorf("monitor %q tls_expiry_warning: %w", m.Name, err)
		}
	}
	return check.Check{Name: strings.TrimSpace(m.Name), Kind: m.Kind, Target: strings.TrimSpace(m.Target),
		Vantage: m.Vantage, Interval: interval, Timeout: timeout, Quorum: m.Quorum,
		Prober: m.Prober, Probers: append([]string(nil), m.Probers...), ExpectStatus: append([]int(nil), m.ExpectStatus...), ExpectBody: m.ExpectBody,
		Send: m.Send, HTTPMethod: m.HTTPMethod, HTTPHeaders: cloneStrings(m.HTTPHeaders),
		HTTPBody: m.HTTPBody, ServerName: m.ServerName, StartTLS: m.StartTLS, DNSRecord: m.DNSRecord,
		DNSServer: m.DNSServer, DNSRCode: m.DNSRCode, GRPCService: m.GRPCService, GRPCTLS: m.GRPCTLS,
		CAFile:           m.CAFile,
		TLSExpiryWarning: tlsExpiryWarning}, nil
}

func cloneStrings(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneMonitor(m MonitorSpec) MonitorSpec {
	m.Probers = append([]string(nil), m.Probers...)
	m.ExpectStatus = append([]int(nil), m.ExpectStatus...)
	m.HTTPHeaders = cloneStrings(m.HTTPHeaders)
	return m
}

func cloneCatalog(in []MonitorSpec) []MonitorSpec {
	out := make([]MonitorSpec, len(in))
	for i := range in {
		out[i] = cloneMonitor(in[i])
	}
	return out
}

func (c *Coordinator) monitorList() []MonitorSpec {
	c.checksMu.RLock()
	out := make([]MonitorSpec, 0, len(c.monitors))
	for _, monitor := range c.monitors {
		out = append(out, cloneMonitor(monitor))
	}
	c.checksMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (c *Coordinator) allChecks() []check.Check {
	c.checksMu.RLock()
	out := make([]check.Check, 0, len(c.checks))
	for _, chk := range c.checks {
		out = append(out, chk)
	}
	c.checksMu.RUnlock()
	return out
}

func (c *Coordinator) checkByName(name string) (check.Check, bool) {
	c.checksMu.RLock()
	chk, ok := c.checks[name]
	c.checksMu.RUnlock()
	return chk, ok
}

func (c *Coordinator) monitorKnown(name string) bool {
	c.checksMu.RLock()
	_, ok := c.monitors[name]
	c.checksMu.RUnlock()
	return ok
}

func (c *Coordinator) validateMonitorCatalog(monitors []MonitorSpec) (map[string]check.Check, error) {
	active := make(map[string]check.Check, len(monitors))
	known := make(map[string]bool, len(monitors))
	for _, monitor := range monitors {
		monitor.Name = strings.TrimSpace(monitor.Name)
		if monitor.Name == "" {
			return nil, errors.New("monitor name is required")
		}
		if known[monitor.Name] {
			return nil, fmt.Errorf("duplicate monitor name %q", monitor.Name)
		}
		known[monitor.Name] = true
		chk, err := monitor.toCheck()
		if err != nil {
			return nil, err
		}
		if err := chk.Validate(); err != nil {
			return nil, err
		}
		if chk.Quorum.Agree > 1 && c.cfg.FanOutTimeout < chk.Timeout+minimumFanOutOverhead {
			return nil, fmt.Errorf("check %q timeout %s leaves no response budget inside fan-out timeout %s; need at least %s",
				chk.Name, chk.Timeout, c.cfg.FanOutTimeout, chk.Timeout+minimumFanOutOverhead)
		}
		eligiblePeers, err := validateEligibleProbers(chk, c.peers, c.byName)
		if err != nil {
			return nil, err
		}
		if chk.Quorum.Of > len(eligiblePeers) {
			return nil, fmt.Errorf("check %q asks %d probers but only %d are eligible", chk.Name, chk.Quorum.Of, len(eligiblePeers))
		}
		if chk.Quorum.DistinctProviders {
			providers := map[string]bool{}
			for _, peer := range eligiblePeers {
				if strings.TrimSpace(peer.Provider) != "" {
					providers[peer.Provider] = true
				}
			}
			if len(providers) < chk.Quorum.Agree {
				return nil, fmt.Errorf("check %q requires %d distinct providers but only %d are configured", chk.Name, chk.Quorum.Agree, len(providers))
			}
		}
		if chk.Prober != "" {
			if _, ok := c.byName[chk.Prober]; !ok {
				return nil, fmt.Errorf("check %q names unregistered prober %q", chk.Name, chk.Prober)
			}
		}
		if monitor.Enabled {
			active[chk.Name] = chk
		}
	}
	for _, component := range c.cfg.Components {
		for _, name := range component.Checks {
			if _, ok := active[name]; !ok {
				return nil, fmt.Errorf("component %q requires enabled monitor %q", component.Name, name)
			}
		}
	}
	candidate := c.cfg
	candidate.Checks = make([]check.Check, 0, len(active))
	for _, chk := range active {
		candidate.Checks = append(candidate.Checks, chk)
	}
	if err := validateNotificationConfig(candidate); err != nil {
		return nil, err
	}
	return active, nil
}

func (c *Coordinator) replaceMonitorCatalog(monitors []MonitorSpec) error {
	active, err := c.validateMonitorCatalog(monitors)
	if err != nil {
		return err
	}
	byName := make(map[string]MonitorSpec, len(monitors))
	for _, monitor := range monitors {
		monitor.Name = strings.TrimSpace(monitor.Name)
		byName[monitor.Name] = cloneMonitor(monitor)
	}
	c.checksMu.Lock()
	c.monitors, c.checks = byName, active
	c.checksMu.Unlock()
	return nil
}

func (c *Coordinator) mutateMonitors(actor, action, subject string, monitors []MonitorSpec) error {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return errors.New("actor is required")
	}
	oldCatalog := c.monitorList()
	if err := c.replaceMonitorCatalog(monitors); err != nil {
		return err
	}
	c.mu.Lock()
	oldRevisions := append([]MonitorRevision(nil), c.monitorRevisions...)
	oldNextRevision := c.nextMonitorRevision
	c.nextMonitorRevision++
	revision := MonitorRevision{ID: c.nextMonitorRevision, At: c.now().UTC(), Actor: actor,
		Action: action, Subject: subject, Catalog: cloneCatalog(c.monitorList())}
	c.monitorRevisions = append(c.monitorRevisions, revision)
	if len(c.monitorRevisions) > maxMonitorRevisions {
		c.monitorRevisions = append([]MonitorRevision(nil), c.monitorRevisions[len(c.monitorRevisions)-maxMonitorRevisions:]...)
	}
	c.mu.Unlock()
	if err := c.persistState(); err != nil {
		_ = c.replaceMonitorCatalog(oldCatalog)
		c.mu.Lock()
		c.monitorRevisions = oldRevisions
		c.nextMonitorRevision = oldNextRevision
		c.mu.Unlock()
		return fmt.Errorf("persist monitor catalogue: %w", err)
	}
	return nil
}

func (c *Coordinator) handleMonitors(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requirePermission(w, r, PermissionView); !ok {
		return
	}
	writeJSON(w, c.monitorList())
}

func (c *Coordinator) handleMonitorOptions(w http.ResponseWriter, _ *http.Request) {
	type option struct {
		Name     string `json:"name"`
		Provider string `json:"provider"`
	}
	out := make([]option, 0, len(c.peers))
	for _, peer := range c.peers {
		out = append(out, option{Name: peer.Name, Provider: peer.Provider})
	}
	writeJSON(w, out)
}

func (c *Coordinator) handleCreateMonitor(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionOperate)
	if !ok {
		return
	}
	var request struct {
		Actor   string      `json:"actor"`
		Monitor MonitorSpec `json:"monitor"`
	}
	if err := decodeOperatorJSON(w, r, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.catalogMu.Lock()
	defer c.catalogMu.Unlock()
	monitors := c.monitorList()
	for _, monitor := range monitors {
		if monitor.Name == strings.TrimSpace(request.Monitor.Name) {
			http.Error(w, "monitor already exists", http.StatusConflict)
			return
		}
	}
	monitors = append(monitors, request.Monitor)
	if err := c.mutateMonitors(mutationActor(principal, request.Actor), "create", request.Monitor.Name, monitors); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, request.Monitor)
}

func (c *Coordinator) handleUpdateMonitor(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionOperate)
	if !ok {
		return
	}
	name := r.PathValue("name")
	var request struct {
		Actor   string      `json:"actor"`
		Monitor MonitorSpec `json:"monitor"`
	}
	if err := decodeOperatorJSON(w, r, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(request.Monitor.Name) != name {
		http.Error(w, "monitor name cannot be changed; clone it instead", http.StatusBadRequest)
		return
	}
	c.catalogMu.Lock()
	defer c.catalogMu.Unlock()
	monitors := c.monitorList()
	found := false
	for i := range monitors {
		if monitors[i].Name == name {
			monitors[i], found = request.Monitor, true
		}
	}
	if !found {
		http.Error(w, "monitor not found", http.StatusNotFound)
		return
	}
	if err := c.mutateMonitors(mutationActor(principal, request.Actor), "update", name, monitors); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, request.Monitor)
}

func (c *Coordinator) handleDeleteMonitor(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionOperate)
	if !ok {
		return
	}
	var request struct {
		Actor string `json:"actor"`
	}
	if err := decodeOperatorJSON(w, r, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := r.PathValue("name")
	c.catalogMu.Lock()
	defer c.catalogMu.Unlock()
	monitors := c.monitorList()
	out := monitors[:0]
	for _, monitor := range monitors {
		if monitor.Name != name {
			out = append(out, monitor)
		}
	}
	if len(out) == len(monitors) {
		http.Error(w, "monitor not found", http.StatusNotFound)
		return
	}
	if err := c.mutateMonitors(mutationActor(principal, request.Actor), "delete", name, out); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) handleValidateMonitor(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requirePermission(w, r, PermissionOperate); !ok {
		return
	}
	var request struct {
		Actor   string      `json:"actor"`
		Monitor MonitorSpec `json:"monitor"`
	}
	if err := decodeOperatorJSON(w, r, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	monitors := c.monitorList()
	replaced := false
	for i := range monitors {
		if monitors[i].Name == request.Monitor.Name {
			monitors[i], replaced = request.Monitor, true
		}
	}
	if !replaced {
		monitors = append(monitors, request.Monitor)
	}
	if _, err := c.validateMonitorCatalog(monitors); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]bool{"valid": true})
}

func (c *Coordinator) handleTestMonitor(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requirePermission(w, r, PermissionOperate); !ok {
		return
	}
	var request struct {
		Actor   string      `json:"actor"`
		Monitor MonitorSpec `json:"monitor"`
		Probers []string    `json:"probers,omitempty"`
	}
	if err := decodeOperatorJSON(w, r, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	chk, err := request.Monitor.toCheck()
	if err == nil {
		err = chk.Validate()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	names := request.Probers
	if len(names) == 0 {
		eligible, eligibleErr := validateEligibleProbers(chk, c.peers, c.byName)
		if eligibleErr != nil {
			http.Error(w, eligibleErr.Error(), http.StatusBadRequest)
			return
		}
		for _, peer := range eligible {
			names = append(names, peer.Name)
		}
	}
	results := make([]MonitorTestResult, len(names))
	ctx, cancel := context.WithTimeout(r.Context(), chk.Timeout+minimumFanOutOverhead)
	defer cancel()
	done := make(chan struct{}, len(names))
	for i, name := range names {
		peer, ok := c.byName[name]
		if !ok {
			http.Error(w, fmt.Sprintf("unknown prober %q", name), http.StatusBadRequest)
			return
		}
		go func(i int, peer Peer) {
			results[i].Prober = peer.Name
			result, err := c.ask(ctx, peer, chk)
			if err != nil {
				results[i].Error = err.Error()
			} else {
				results[i].Result = result
			}
			done <- struct{}{}
		}(i, peer)
	}
	for range names {
		<-done
	}
	writeJSON(w, results)
}

func (c *Coordinator) monitorRevisionList() []MonitorRevision {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]MonitorRevision, len(c.monitorRevisions))
	for i, revision := range c.monitorRevisions {
		out[i] = revision
		out[i].Catalog = cloneCatalog(revision.Catalog)
	}
	return out
}

func (c *Coordinator) handleMonitorRevisions(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requirePermission(w, r, PermissionView); !ok {
		return
	}
	writeJSON(w, c.monitorRevisionList())
}

func (c *Coordinator) handleRollbackMonitors(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionRollback)
	if !ok {
		return
	}
	var request struct {
		Actor string `json:"actor"`
	}
	if err := decodeOperatorJSON(w, r, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid revision id", http.StatusBadRequest)
		return
	}
	c.catalogMu.Lock()
	defer c.catalogMu.Unlock()
	var target []MonitorSpec
	for _, revision := range c.monitorRevisionList() {
		if revision.ID == id {
			target = revision.Catalog
			break
		}
	}
	if target == nil {
		http.Error(w, "revision not found", http.StatusNotFound)
		return
	}
	if err := c.mutateMonitors(mutationActor(principal, request.Actor), "rollback", fmt.Sprint(id), target); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, c.monitorList())
}
