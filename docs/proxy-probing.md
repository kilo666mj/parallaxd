# Proxy probing

HTTP monitors can reach HTTP or HTTPS targets through named HTTP, HTTPS, or
SOCKS5 proxy profiles. Leave `proxy_profile` empty for the existing direct path.
Raw TCP checks, other check kinds, SOCKS UDP, proxy chaining, and remote target
DNS (`socks5h`) are not supported.

HTTP and HTTPS proxies must support **CONNECT to the target port**, including
port 80 for plain HTTP targets. Forward-only HTTP proxies are incompatible.
Tunnelling preserves the target's original Host header and HTTPS SNI while
letting the prober enforce destination policy against the exact IP sent to the
proxy. Target TLS verification remains enabled. HTTPS proxy TLS uses its own
trust configuration; it does not inherit the target monitor's additional CA.

## Configure the route

Add profiles to each participating prober's `probe.json`:

```json
{
  "proxy_profiles": {
    "external": {
      "url": "https://proxy.example.net:8443",
      "egress": "exit-west",
      "credentials_file": "/etc/parallaxd/proxy-credentials/external.json",
      "ca_file": "/etc/parallaxd/ca/proxy.pem"
    }
  }
}
```

`credentials_file` and `ca_file` are optional. The credentials file contains
`{"username":"…","password":"…"}` and must be readable by the prober service
account. Keep it root-owned and mode `0640` with the service group. Files are
reread for each probe, so credentials and CA certificates can rotate without a
restart. Additional CA files must stay under `/etc/parallaxd/ca`, including after
symlink resolution. Proxy credentials are HTTP Basic or SOCKS5 username/password;
only an HTTPS proxy encrypts the proxy authentication exchange itself.
URLs cannot contain user information, query parameters, fragments, or paths.
Default ports are 80 for HTTP, 443 for HTTPS, and 1080 for SOCKS5.

Register only the profile name and exit identity for that peer in the
coordinator's `probers` configuration:

```json
{
  "name": "probe-a",
  "proxy_profiles": {"external": "exit-west"}
}
```

These snippets augment the existing configurations. The coordinator never needs
the proxy URL or credentials. Add `"proxy_profile": "external"` to an HTTP
monitor through configuration, the monitor API/MCP, or the dashboard's advanced
settings. Assignment and corroboration use only peers registered for that
profile. An explicitly selected peer without that profile fails validation.
Profile and exit identifiers use 1–64 ASCII letters, digits, dots, underscores,
or hyphens and must begin with a letter or digit.

Give every shared exit the **same egress identity across the fleet**, even if
probers use different proxy endpoints or credentials. Give separately operated
exits different identities. This is operator-maintained topology, not automatic
public-IP detection; a load-balanced or rotating proxy pool should have one
identity for the shared pool. Signed results must match the coordinator's
registered profile and exit exactly.

## DNS, destination policy, and evidence

The prober resolves target hostnames locally and checks all returned addresses
against its existing vantage, allowlist, and denylist rules before requesting a
tunnel. It sends only those checked numeric addresses to the proxy; the proxy
never resolves the target hostname. Redirect destinations undergo the same
checks. A mixed allowed/forbidden DNS answer fails closed. Internal checks still
require the production prober's explicit target allowlist. A target that exists
only in the proxy's DNS view needs a locally resolvable name before it can be
monitored this way.

A local profile explicitly grants access to its proxy endpoint, independently of
monitor target allowlists. Permanent metadata, link-local, multicast, and
unspecified-address blocks still apply to that endpoint. The proxy is trusted to
honour the requested numeric destination. No environment proxy settings or direct
fallback are used.

Missing profiles, local credentials or CA failures, destination-policy rejection,
and proxy connection, TLS, authentication, or tunnel-establishment failures
produce `unknown`. They are not evidence that the target is down. Once the tunnel
is established, target TLS, HTTP status, body, and response-timeout failures use
the normal target `down` semantics. A CONNECT/SOCKS refusal cannot reliably
separate proxy policy from target failure, so it remains `unknown` too. Error
details omit proxy endpoints, credentials, and upstream proxy response text.

Several results through one exit count as one independent vote, even when
`distinct_providers` is false. When provider diversity is required, the same set
of votes must have distinct hosting providers **and** distinct exits. Catalogue
validation rejects a quorum that the registered topology cannot satisfy;
corroboration favours independent routes. Outage confirmation and recovery use
the same rule. Steady-state successful checks still run on one assigned prober.
Observations and test results include `proxy_profile` and `egress`; the dashboard
shows routes in the registry, test results, and history timeline tooltips.

## Ansible and rollout

Define `parallaxd_proxy_profiles` per prober host using the same structure as
`proxy_profiles`. Put secrets in a vaulted `parallaxd_proxy_credentials` map:

```yaml
parallaxd_proxy_profiles:
  external:
    url: https://proxy.example.net:8443
    egress: exit-west
    credentials_file: /etc/parallaxd/proxy-credentials/external.json
parallaxd_proxy_credentials:
  external:
    username: "{{ vault_proxy_username }}"
    password: "{{ vault_proxy_password }}"
```

Ansible installs these credentials only on the prober, with secret task output
suppressed. The coordinator template extracts only names and egress identities.
Use `parallaxd_ca_files` for additional proxy CAs as for target CAs. Endpoint or
profile changes restart the prober; credential rotation alone does not.

Upgrade the primary, standby, and participating probers and register their
profiles before adding proxy monitors. An older prober that ignores the route
field produces an `unknown` result at an upgraded coordinator. Once a catalogue
or retained catalogue revision contains a proxy monitor, persisted and replicated
state uses version 7, which older coordinators reject. Direct-only catalogues
continue to emit version 6. Do not downgrade a proxy-enabled coordinator or
standby. Test each monitor's selected routes before enabling it; independent
exits must be configured to meet its quorum.
