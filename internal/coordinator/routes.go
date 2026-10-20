package coordinator

import "net/http"

// Handler serves the coordinator's HTTP surface.
func (c *Coordinator) Handler() http.Handler {
	mux := http.NewServeMux()
	if c.mcp != nil {
		mux.HandleFunc("POST /mcp", c.viewOnly(c.mcp.ServeHTTP))
	}
	mux.HandleFunc("POST /v1/results", c.handleResult)
	mux.HandleFunc("GET /v1/health", c.handleHealth)
	mux.HandleFunc("GET /v1/status", c.viewOnly(c.handleStatus))
	mux.HandleFunc("POST /v1/mesh", c.handleMesh)
	mux.HandleFunc("GET /v1/mesh", c.viewOnly(c.handleMeshView))
	mux.HandleFunc("GET /v1/peers", c.handlePeers)
	mux.HandleFunc("GET /v1/components", c.viewOnly(c.handleComponents))
	mux.HandleFunc("GET /v1/export", c.handleExport)
	mux.HandleFunc("GET /v1/assignments", c.viewOnly(c.handleAssignments))
	mux.HandleFunc("GET /v1/checks", c.handleChecks)
	mux.HandleFunc("GET /v1/incidents", c.viewOnly(c.handleIncidents))
	mux.HandleFunc("POST /v1/incidents/{id}/acknowledge", c.handleAcknowledgeIncident)
	mux.HandleFunc("POST /v1/incidents/{id}/resolve", c.handleResolveIncident)
	mux.HandleFunc("GET /v1/maintenance", c.viewOnly(c.handleMaintenance))
	mux.HandleFunc("POST /v1/maintenance", c.handlePutMaintenance)
	mux.HandleFunc("PUT /v1/maintenance/{name}", c.handlePutMaintenance)
	mux.HandleFunc("DELETE /v1/maintenance/{name}", c.handleDeleteMaintenance)
	mux.HandleFunc("GET /v1/notices", c.viewOnly(c.handleNotices))
	mux.HandleFunc("POST /v1/notices", c.handleCreateNotice)
	mux.HandleFunc("POST /v1/notices/{id}/updates", c.handlePostNoticeUpdate)
	mux.HandleFunc("PUT /v1/notices/{id}", c.handleEditNotice)
	mux.HandleFunc("DELETE /v1/notices/{id}", c.handleDeleteNotice)
	mux.HandleFunc("GET /v1/silences", c.viewOnly(c.handleSilences))
	mux.HandleFunc("POST /v1/silences", c.handleCreateSilence)
	mux.HandleFunc("DELETE /v1/silences/{id}", c.handleDeleteSilence)
	mux.HandleFunc("GET /v1/diagnostics", c.viewOnly(c.handleDiagnostics))
	mux.HandleFunc("GET /v1/deliveries", c.viewOnly(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, c.Outbox()) }))
	mux.HandleFunc("GET /v1/history", c.viewOnly(c.handleHistory))
	mux.HandleFunc("GET /v1/history/summary", c.viewOnly(c.handleHistorySummary))
	mux.HandleFunc("GET /v1/uptime", c.viewOnly(c.handleUptime))
	mux.HandleFunc("GET /v1/metrics/hosts", c.viewOnly(c.handleHostMetrics))
	mux.HandleFunc("GET /metrics", c.viewOnly(c.handleMetrics))
	mux.HandleFunc("GET /v1/auth/me", c.handleAuthMe)
	mux.HandleFunc("POST /v1/auth/login", c.handleLogin)
	mux.HandleFunc("POST /v1/auth/logout", c.handleLogout)
	mux.HandleFunc("POST /v1/auth/password", c.handleChangePassword)
	mux.HandleFunc("GET /v1/auth/oidc/start", c.handleOIDCStart)
	mux.HandleFunc("GET /v1/auth/oidc/callback", c.handleOIDCCallback)
	mux.HandleFunc("GET /v1/auth/users", c.handleUsers)
	mux.HandleFunc("POST /v1/auth/users", c.handleUsers)
	mux.HandleFunc("PUT /v1/auth/users/{username}", c.handleUser)
	mux.HandleFunc("DELETE /v1/auth/users/{username}", c.handleUser)
	mux.HandleFunc("GET /v1/auth/tokens", c.handleTokens)
	mux.HandleFunc("POST /v1/auth/tokens", c.handleTokens)
	mux.HandleFunc("DELETE /v1/auth/tokens/{id}", c.handleToken)
	mux.HandleFunc("GET /v1/monitors", c.handleMonitors)
	mux.HandleFunc("GET /v1/monitor-options", c.viewOnly(c.handleMonitorOptions))
	mux.HandleFunc("POST /v1/monitors", c.handleCreateMonitor)
	mux.HandleFunc("PUT /v1/monitors/{name}", c.handleUpdateMonitor)
	mux.HandleFunc("DELETE /v1/monitors/{name}", c.handleDeleteMonitor)
	mux.HandleFunc("POST /v1/monitors/validate", c.handleValidateMonitor)
	mux.HandleFunc("POST /v1/monitors/test", c.handleTestMonitor)
	mux.HandleFunc("GET /v1/monitors/revisions", c.handleMonitorRevisions)
	mux.HandleFunc("POST /v1/monitors/revisions/{id}/rollback", c.handleRollbackMonitors)
	mux.HandleFunc("GET /v1/replica", c.handleReplica)
	mux.HandleFunc("GET /v1/ha", c.viewOnly(c.handleHAStatus))
	mux.HandleFunc("POST /v1/ha/promote", c.handlePromote)
	mux.HandleFunc("GET /assets/parallaxd-icon.png", c.handleIcon)
	mux.HandleFunc("GET /", c.handleDashboard)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.isStandby() && standbyBlocks(r) {
			http.Error(w, "coordinator is a read-only standby", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (c *Coordinator) viewOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Embedders may construct an in-memory coordinator without an operator
		// plane. The production command rejects such a configuration.
		if !c.authEnabled() {
			next(w, r)
			return
		}
		if _, ok := c.requirePermission(w, r, PermissionView); !ok {
			return
		}
		next(w, r)
	}
}
