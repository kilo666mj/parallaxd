// Package mcpserver exposes Parallaxd's authenticated operator API as MCP
// tools for locally launched agents.
package mcpserver

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/parallaxd/internal/coordinator"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type emptyInput struct{}

type document struct {
	Data any `json:"data" jsonschema:"JSON returned by the Parallaxd coordinator"`
}

type monitorDocument struct {
	Monitor coordinator.MonitorSpec `json:"monitor" jsonschema:"complete typed monitor definition accepted by the Parallaxd monitor API"`
}

type namedMonitorDocument struct {
	Name    string                  `json:"name" jsonschema:"existing monitor name"`
	Monitor coordinator.MonitorSpec `json:"monitor" jsonschema:"complete typed replacement monitor definition; its name must match name"`
}

type namedMonitor struct {
	Name string `json:"name" jsonschema:"existing monitor name"`
}

type testMonitorInput struct {
	Monitor coordinator.MonitorSpec `json:"monitor" jsonschema:"complete typed monitor definition to test without saving"`
	Probers []string                `json:"probers,omitempty" jsonschema:"optional prober names; omit to use all eligible probers"`
}

type rollbackInput struct {
	RevisionID uint64 `json:"revision_id" jsonschema:"catalogue revision ID returned by parallaxd_list_monitor_revisions"`
}

type historyInput struct {
	Check string `json:"check,omitempty" jsonschema:"optional monitor name"`
	Since string `json:"since,omitempty" jsonschema:"optional RFC3339 lower time bound"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum observations from 1 through 10000; defaults to 1000"`
}

func New(client Client, version string) *mcp.Server {
	server := mcpkit.MustServer(mcpkit.ServerConfig{Name: "parallaxd", Version: version,
		Instructions: "Use Parallaxd tools to inspect corroborated availability and manage the live monitor catalogue. Validate and test monitors before saving changes."})
	addGetTool(server, client, "parallaxd_get_status", "Read the current status and assignment of every enabled monitor.", "/v1/status")
	addGetTool(server, client, "parallaxd_list_monitors", "List complete enabled and disabled monitor definitions.", "/v1/monitors")
	addGetTool(server, client, "parallaxd_get_incidents", "Read active and resolved incidents, newest first.", "/v1/incidents")
	addGetTool(server, client, "parallaxd_get_components", "Read service-level component status.", "/v1/components")
	addGetTool(server, client, "parallaxd_get_diagnostics", "Read coordinator, queue, notification, and HA diagnostics.", "/v1/diagnostics")
	addGetTool(server, client, "parallaxd_get_history_summary", "Read retained availability and latency summaries for all monitors.", "/v1/history/summary")
	addGetTool(server, client, "parallaxd_get_monitor_options", "List registered probers and providers available for monitor ownership and corroboration.", "/v1/monitor-options")
	addGetTool(server, client, "parallaxd_list_monitor_revisions", "Read monitor catalogue revision history for audit and recovery.", "/v1/monitors/revisions")

	mcp.AddTool(server, &mcp.Tool{Name: "parallaxd_get_history", Description: "Read retained observations, optionally filtered by monitor and time.", Annotations: mcpkit.ReadOnly(false)},
		func(ctx context.Context, _ *mcp.CallToolRequest, input historyInput) (*mcp.CallToolResult, document, error) {
			values := url.Values{}
			if input.Check != "" {
				values.Set("check", input.Check)
			}
			if input.Since != "" {
				values.Set("since", input.Since)
			}
			if input.Limit != 0 {
				if input.Limit < 1 || input.Limit > 10000 {
					return nil, document{}, fmt.Errorf("limit must be 1..10000")
				}
				values.Set("limit", strconv.Itoa(input.Limit))
			}
			path := "/v1/history"
			if query := values.Encode(); query != "" {
				path += "?" + query
			}
			return fetch(ctx, client, path)
		})

	mcp.AddTool(server, &mcp.Tool{Name: "parallaxd_validate_monitor", Description: "Validate a monitor against the live fleet without saving or probing it.", Annotations: mcpkit.ReadOnly(false)},
		func(ctx context.Context, _ *mcp.CallToolRequest, input monitorDocument) (*mcp.CallToolResult, document, error) {
			return mutate(ctx, func(out *any) error {
				return client.Post(ctx, "/v1/monitors/validate", monitorEnvelope(client, input.Monitor), out)
			})
		})
	mcp.AddTool(server, &mcp.Tool{Name: "parallaxd_test_monitor", Description: "Run an on-demand monitor test through eligible or explicitly named probers without saving it.", Annotations: mcpkit.ReadOnly(true)},
		func(ctx context.Context, _ *mcp.CallToolRequest, input testMonitorInput) (*mcp.CallToolResult, document, error) {
			body := struct {
				Actor   string                  `json:"actor,omitempty"`
				Monitor coordinator.MonitorSpec `json:"monitor"`
				Probers []string                `json:"probers,omitempty"`
			}{Actor: client.Actor, Monitor: input.Monitor, Probers: input.Probers}
			return mutate(ctx, func(out *any) error { return client.Post(ctx, "/v1/monitors/test", body, out) })
		})
	mcp.AddTool(server, &mcp.Tool{Name: "parallaxd_create_monitor", Description: "Validate, save, version, and activate a new monitor. Requires an operator or admin token.", Annotations: mcpkit.Mutating(false, false)},
		func(ctx context.Context, _ *mcp.CallToolRequest, input monitorDocument) (*mcp.CallToolResult, document, error) {
			return mutate(ctx, func(out *any) error {
				return client.Post(ctx, "/v1/monitors", monitorEnvelope(client, input.Monitor), out)
			})
		})
	mcp.AddTool(server, &mcp.Tool{Name: "parallaxd_update_monitor", Description: "Validate and replace an existing monitor while recording a catalogue revision. Requires an operator or admin token.", Annotations: mcpkit.Destructive(false, false)},
		func(ctx context.Context, _ *mcp.CallToolRequest, input namedMonitorDocument) (*mcp.CallToolResult, document, error) {
			if strings.TrimSpace(input.Name) == "" {
				return nil, document{}, fmt.Errorf("name is required")
			}
			path := "/v1/monitors/" + url.PathEscape(input.Name)
			return mutate(ctx, func(out *any) error {
				return client.Put(ctx, path, monitorEnvelope(client, input.Monitor), out)
			})
		})
	mcp.AddTool(server, &mcp.Tool{Name: "parallaxd_delete_monitor", Description: "Delete a monitor and record a catalogue revision. Requires an operator or admin token.", Annotations: mcpkit.Destructive(false, false)},
		func(ctx context.Context, _ *mcp.CallToolRequest, input namedMonitor) (*mcp.CallToolResult, document, error) {
			if strings.TrimSpace(input.Name) == "" {
				return nil, document{}, fmt.Errorf("name is required")
			}
			path := "/v1/monitors/" + url.PathEscape(input.Name)
			if err := client.Delete(ctx, path, map[string]string{"actor": client.Actor}); err != nil {
				return nil, document{}, err
			}
			return nil, document{Data: map[string]any{"deleted": true, "name": input.Name}}, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "parallaxd_rollback_monitors", Description: "Replace the live catalogue with a reviewed historical revision. Requires an admin token.", Annotations: mcpkit.Destructive(false, false)},
		func(ctx context.Context, _ *mcp.CallToolRequest, input rollbackInput) (*mcp.CallToolResult, document, error) {
			if input.RevisionID == 0 {
				return nil, document{}, fmt.Errorf("revision_id is required")
			}
			path := "/v1/monitors/revisions/" + strconv.FormatUint(input.RevisionID, 10) + "/rollback"
			return mutate(ctx, func(out *any) error {
				return client.Post(ctx, path, map[string]string{"actor": client.Actor}, out)
			})
		})
	return server
}

func addGetTool(server *mcp.Server, client Client, name, description, path string) {
	mcp.AddTool(server, &mcp.Tool{Name: name, Description: description, Annotations: mcpkit.ReadOnly(false)},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, document, error) {
			return fetch(ctx, client, path)
		})
}

func fetch(ctx context.Context, client Client, path string) (*mcp.CallToolResult, document, error) {
	var data any
	if err := client.Get(ctx, path, &data); err != nil {
		return nil, document{}, err
	}
	return nil, document{Data: data}, nil
}

func mutate(ctx context.Context, call func(*any) error) (*mcp.CallToolResult, document, error) {
	var data any
	if err := call(&data); err != nil {
		return nil, document{}, err
	}
	return nil, document{Data: data}, nil
}

func monitorEnvelope(client Client, monitor coordinator.MonitorSpec) any {
	return struct {
		Actor   string                  `json:"actor,omitempty"`
		Monitor coordinator.MonitorSpec `json:"monitor"`
	}{Actor: client.Actor, Monitor: monitor}
}
