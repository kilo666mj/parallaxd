# MCP agent access

The coordinator serves a stateless Streamable HTTP MCP endpoint at `POST /mcp`.
It exposes typed tools for fleet status, incidents, diagnostics, history, and
the versioned monitor catalogue.

MCP is another authenticated interface to the existing operator API, not a
second control plane. The bearer token from each MCP request is used for every
underlying API call, so the coordinator remains responsible for role checks,
monitor validation, audit identity, persistence, and HA replication.

## Choose a role

Create a dedicated service credential from the dashboard's **Access control**
page. Give each client its own token so it can be revoked and audited
independently.

| Role | MCP capabilities |
|---|---|
| `viewer` | Read status, monitors, incidents, components, diagnostics, history, monitor options, and catalogue revisions |
| `operator` | All viewer tools plus validate, test, create, update, and delete monitors |
| `admin` | All operator tools plus catalogue rollback |

Start with `viewer`. Upgrade the credential only when the client has a real
need to change the catalogue. Tool annotations and client approval prompts are
defense in depth; the coordinator enforces the role even if a client ignores
those hints.

The secret is shown only once. Store it in a secret manager or a mode-0600
file. Never put it in a URL, shell history, tracked configuration, logs, or a
prompt.

## Network exposure

Give the MCP client a URL ending in `/mcp`, for example:

```text
https://status.example.com/mcp
```

Expose that route only through the same trusted TLS reverse proxy, source
allowlist, VPN, or private network used for the operator API. MCP authentication
does not make plaintext traffic confidential and does not replace rate or
concurrency limits at a public edge.

For a coordinator that is intentionally reachable only on loopback, forward
the existing coordinator listener instead of opening a new firewall port:

```sh
ssh -N -L 127.0.0.1:18972:127.0.0.1:8972 coordinator.example
```

The client URL is then `http://127.0.0.1:18972/mcp`. Keep the tunnel alive for
as long as the client uses MCP. For unattended use, manage it with the site's
normal service supervisor and SSH host-key policy.

## Configure Codex

The preferred setup keeps the bearer token in an environment variable:

```sh
export PARALLAXD_MCP_TOKEN='the-one-time-secret'
codex mcp add parallaxd \
  --url https://status.example.com/mcp \
  --bearer-token-env-var PARALLAXD_MCP_TOKEN
```

For finer-grained policy, the equivalent `~/.codex/config.toml` entry is:

```toml
[mcp_servers.parallaxd]
url = "https://status.example.com/mcp"
bearer_token_env_var = "PARALLAXD_MCP_TOKEN"
default_tools_approval_mode = "writes"
```

`writes` asks before tools not marked read-only. A `viewer` token remains
read-only at the coordinator regardless of this client setting.

The variable must exist in the environment of the Codex process itself. An
interactive shell export does not update an already-running desktop app or IDE
extension. Fully restart that client from an environment that contains the
variable after changing environment configuration.

If process-level environment injection is unavailable, Codex also supports a
static header in its private user configuration:

```toml
[mcp_servers.parallaxd]
url = "https://status.example.com/mcp"
http_headers = { Authorization = "Bearer REPLACE_WITH_SECRET" }
default_tools_approval_mode = "writes"
```

Keep `~/.codex/config.toml` mode `0600` when it contains a credential. Do not
use a static header in project-scoped or committed configuration.

Restart Codex after changing MCP configuration. The CLI, IDE extension, and
desktop app share the same host-level Codex MCP configuration.

## Verify access

First confirm that Codex loaded the server:

```sh
codex mcp list
```

Then ask the agent to list Parallaxd monitor status or call
`parallaxd_get_status`. A viewer credential should be able to call read tools
and should receive `permission denied` from a mutating tool.

Expected failures help locate configuration problems:

| Symptom | Meaning |
|---|---|
| Environment variable is not set | The Codex process did not inherit the variable named by `bearer_token_env_var` |
| `401 authentication required` | The header is missing, malformed, revoked, or unknown |
| `403 permission denied` | Authentication succeeded but the token role does not allow that tool operation |
| Connection refused or timeout | The TLS proxy, private route, SSH tunnel, or coordinator is unavailable |
| A browser or plain `GET` does not return MCP data | Expected: the stateless endpoint accepts MCP protocol requests over `POST`; verify it with an MCP client |

## Rotate or remove access

1. Issue a replacement token with the same minimum role.
2. Update the client's secret source and restart or reconnect it.
3. Verify a read call with the replacement.
4. Revoke the old credential from **Access control**.
5. Confirm the old credential now receives `401`.

Remove the client entry with `codex mcp remove parallaxd` when access is no
longer needed. Also remove any private tunnel service and local secret copy.
