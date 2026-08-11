# parallaxd

Corroborated availability monitoring: check from one place, confirm from
several, alert only when they agree.

Parallax is the apparent shift of an object viewed from two separated points,
and the method by which its distance is established. That is the idea here — a
single viewpoint cannot establish the fact, separated viewpoints can.

> **Status: operational.** Coordinator, public and private probers, watcher and
> warm standby are deployed; signed dynamic assignments, automatic failover,
> durable operations, monitor management and the status dashboard are included.
> The current milestone is operational assurance and integration coverage; see
> the [roadmap](ROADMAP.md).

## The problem

**A single prober cannot tell "the service is down" from "my path to the
service is down."** Most false alerts are the second thing — an uplink blip, a
route flap, a resolver hiccup — and they are indistinguishable from a real
outage at the point of measurement.

So: one prober runs each check on a schedule. When it sees a failure, the
coordinator asks others to probe the same target *now*, and alerts only if
enough of them agree.

That ordering matters. Continuous multi-prober monitoring costs N × M probes
forever; corroborating only on suspicion costs M in steady state and N during
an incident. The difference is what makes expensive checks affordable — a full
SMTP conversation, a TLS handshake with certificate validation, an
authenticated HTTP transaction. Those are the checks worth having, and exactly
the ones nobody runs from twelve places every minute.

## Two distinctions the design rests on

Both are easy to collapse by accident, and collapsing either turns a
corroborating monitor into a noisier version of a single prober.

### Down is not Unknown

A result is one of three things:

| Status | Meaning | Counts as evidence? |
|---|---|---|
| `up` | the probe completed and the target behaved | yes |
| `down` | the probe completed and the target did not | yes |
| `unknown` | **this prober could not form an opinion** | **no** |

A prober whose own resolver is broken has learned nothing about the target.
Counting that as a vote for `down` is precisely how a corroborating monitor
manufactures the false alerts it exists to prevent — and how a network-isolated
node, which can reach nothing, reports that everything is broken.

The boundary is: a failure that required reaching the target to observe is
evidence (refused, reset, timed out — someone declined to answer). A failure
that happened before the target was ever contacted is not (local DNS failed, no
route at all, the attempt was cancelled).

Timeouts are deliberately evidence, even though a broken network also produces
them. A genuinely cut-off prober times out on *everything*, which the
fleet-wide view catches; second-guessing each individual timeout would suppress
real outages.

### A check must declare its vantage

```go
Vantage: check.VantagePublic   // must traverse the public internet
Vantage: check.VantageInternal // over a VPN, mesh or LAN
```

There is no default, and an unset vantage fails validation. On a fleet with a
private mesh, "reachable over WireGuard" and "reachable from the internet" are
different claims. A corroborator that answers the wrong one produces a
confident all-clear about a question nobody asked — worse than the false
positive it was meant to remove.

## What a verdict says

Quorum evaluation is pure — results in, verdict out, no clock and no I/O — and
it applies these rules in order:

- **A result answering a different question is discarded**, not counted: wrong
  check, wrong vantage, or too old. Discards are reported, so a
  misconfiguration surfaces instead of silently weakening the quorum.
- **A prober votes once.** Otherwise one node that retries — or replays — can
  manufacture a quorum by itself. The newest result from a prober wins, so a
  retry supersedes the failure it followed.
- **Unknown is not a vote.**
- **Down wins if it reaches quorum, even when others report up.** A target
  reachable from two vantages and unreachable from three is having an outage,
  and reporting "up" because somebody got through would hide it.
- **A prober that can reach no peer is not counted at all.** Its results are
  not weak evidence to be outvoted; they are not evidence. See
  [the mesh](#the-mesh-telling-i-cannot-reach-this-from-i-cannot-reach-anything).
- **Without enough evidence the verdict is inconclusive, never up.** Silence is
  not an all-clear.

Optionally a quorum can require the agreeing probers to sit behind **distinct
providers** — three probers at one host are one opinion held three times. That
rule fails closed: probers with no provider recorded collapse into a single
group, so an unlabelled fleet cannot satisfy it by accident.

Verdicts carry the count, the dissenters and the providers, because an alert
that cannot say *"3 of 5 across three providers, 2 still reported up"* is not
actionable.

## Architecture

A coordinator with probers, not peer-to-peer consensus.

| Binary | Role |
|---|---|
| `parallaxd` | coordinator: assigns checks, requests corroboration, applies quorum, owns alerting and deduplication |
| `parallaxd-probe` | prober: runs checks, answers corroboration requests, **decides nothing** |
| `parallaxd-watch` | the far end of the dead-man's switch: receives the heartbeat, alerts when it stops |

Peer-to-peer sounds better and is where these projects die — leader election,
split brain, and eventually a worse Raft. A coordinator being down is a
monitoring gap rather than an outage: probers keep probing and nothing alerts.
That is what [the dead-man's switch](#the-dead-mans-switch) exists to make
noticeable.

Probers do talk to each other, for [the mesh checks](#the-mesh-telling-i-cannot-reach-this-from-i-cannot-reach-anything).
That is traffic, not authority: they report what they saw and the coordinator
decides what it means. A prober that could conclude it was isolated could also
decline to, which is exactly the power this design keeps out of them.

## Both directions are signed

A prober's result is a claim about the world that the coordinator counts toward
a verdict — and quorum de-duplication trusts the prober name on it. If that
name were an unauthenticated string, anything that could reach the coordinator
could manufacture agreement and alert on a healthy service, or forge `up`
results and suppress a real outage.

A coordinator's request is an instruction to open a connection to an arbitrary
target, right now. Unauthenticated, that turns the fleet into a **probe
amplifier**: one request fans out to every prober, aimed wherever the sender
likes. Signing requests is what keeps a monitoring system from becoming an
attack tool.

Ed25519 throughout, with:

- **Sign the bytes you send.** The transmitted payload *is* the signed payload;
  nothing re-serializes and hopes it matches.
- **Domain separation.** A captured result cannot verify as a request, so it
  cannot be replayed to make probers connect somewhere.
- **Identity binding.** The signature proves who signed; a second check proves
  the payload claims the same identity. Otherwise one prober could sign results
  attributed to another and vote twice.
- **Audience-bound, one-shot nonces and expiry on requests**, so a result
  answers only the request it was produced for and a captured request cannot be
  replayed or relayed to another prober.
- **Clock-skew bounds**, so a prober with a badly wrong clock produces a visible
  error rather than results that outlive every staleness check downstream.
- **A bounded payload**, checked before the key lookup and before any allocation
  derived from it. The length is the one field an unauthenticated sender fully
  controls.

## Running a prober

```sh
parallaxd-probe -genkey        # private half to the agent, public half to the coordinator
parallaxd-probe -config /etc/parallaxd/probe.json
```

A prober will open a socket to an arbitrary address when told to, which is a
useful thing to own if you are not its owner. So the order of operations in the
request handler is the point: read a bounded body, verify the signature, and
only then connect to anything. An unverifiable request produces **no traffic at
all** — not a refused probe reported as down, not a connection that is opened
and discarded. `TestUnverifiedRequestCausesNoTraffic` asserts that against a
listener that counts connections, with a valid request as the control so the
test cannot pass by everything being broken.

A prober holds no policy. Whether a target is down, whether enough probers
agree, and whether anyone needs telling all belong to the coordinator — so a
compromised prober can misreport what it saw, but cannot decide anything.

### Where a prober may connect

Signing establishes *who* asked, not *what may be asked for*. A coordinator
with a bug — or one that has been taken over — could otherwise aim every prober
in the fleet at a cloud metadata endpoint or an internal admin panel, and
probers sit inside networks precisely where that is worth something.

The vantage a check already has to declare answers this:

- **Nothing may reach link-local.** `169.254.169.254` and `fe80::/10` are where
  cloud metadata lives, and no availability check legitimately targets them.
- **A public-vantage check may not reach loopback or private space.** Such a
  check is incoherent — it claims to test what a user on the internet sees, and
  no user on the internet reaches `10.0.0.1`.
- **An internal-vantage check may**, because that is what it is for.

And the operator can narrow it further, per prober:

```jsonc
{
  "allow_targets": ["10.0.0.0/8", "192.0.2.0/24"],  // exhaustive when set
  "deny_targets":  ["10.9.0.0/16"]                  // deny wins
}
```

That closes what the vantage rules alone leave open: an internal-vantage check
may otherwise reach anything private, which is a pivot if the coordinator is
taken over. The coordinator says what is worth checking; **the host's owner
says what is reachable at all**, and the second is not overridable by the
first — an allowlist of `0.0.0.0/0` still cannot re-enable the metadata
address.

All of it is enforced in `Dialer.Control`, against the resolved address, on
every connection attempt. Validating the hostname up front would be a
DNS-rebinding hole: the name resolves to something allowed, then the dial
resolves it again to something else. A blocked target yields `unknown`, never
`down` — it says the check is misconfigured, not that the service is broken.

## What the coordinator does

`parallaxd` is the only component that decides anything. An incident:

```
prober reports down  ->  ask Of-1 others, concurrently, with a deadline
                     ->  quorum.Evaluate over everything that came back
                     ->  state machine: alert only on a transition
```

### Check kinds

| Kind | Verification |
|---|---|
| `tcp` | connection accepted |
| `http` | configurable method, headers and body; expected status/body |
| `banner` | greeting substring, with an optional polite close command |
| `dns` | A, AAAA, MX or TXT records, with optional expected content |
| `tls` | certificate-verified TLS 1.2+ handshake |
| `smtp` | greeting, EHLO, optional STARTTLS and NOOP transaction |
| `icmp` | echo request/reply; deployment grants only `CAP_NET_RAW` to the prober |

HTTP headers can carry authentication, but remember that control traffic is
authenticated rather than encrypted: without a private transport, an on-path
observer can read check definitions, including configured headers.

**Only a failure is worth asking about.** An `up` result already answers the
question, so corroborating it would spend N probes to confirm what one prober
can see — the cost model this design exists to avoid. A check whose quorum a
single report already satisfies (`agree: 1`) skips the fan-out too.

**The reporting prober is never asked again.** It has voted; quorum would
de-duplicate it anyway, so asking would spend a probe to learn nothing.

**Silence is not a vote.** A corroborator that does not answer inside the
deadline contributes nothing rather than counting as agreement or dissent. The
quorum simply goes unmet, and an unmet quorum stays quiet.

**Alerts fire on transitions, never on results.** A genuine outage produces a
failing result every interval for as long as it lasts; an alert per result is
what trains people to filter the channel. Down alerts once, recovery alerts
once, and an **inconclusive verdict does not clear a down** — not being able to
confirm an outage is not evidence that it ended.

An inconclusive failure is retained as a **suspect timeline** rather than
disappearing. `GET /v1/status`, `GET /v1/export`, and `GET /v1/diagnostics`
expose the first suspicion, latest corroboration attempt and duration, attempt
count, and latest reason quorum could not decide. If later evidence confirms
the outage, the alert carries both the decision time and the original
`suspected_at`, making detection latency visible instead of rewriting the
outage as having begun when the fleet finally agreed.

A first-ever `up` is not a recovery either. Announcing "recovered" for
everything at startup is the other way a monitoring channel gets muted.

Assignment uses an explicit preferred owner when configured and rendezvous
hashing otherwise. Probers fetch their signed-credential-protected assignment
set from the coordinator and reconcile schedules without restarting. A silent
or isolated owner is removed from the candidate set until it reports or
rejoins. `GET /v1/assignments` exposes the effective view; `GET /v1/status`
shows the current verdict per check.

### Alerting

A `Notifier` interface with two generic implementations: a log, and a webhook
that POSTs the alert as JSON. Anything that knows about a particular chat
product or monitoring system belongs outside this repository — parallaxd should
be useful to someone running none of the same infrastructure, and the webhook is
where their own glue attaches.

Webhook delivery is durable. Each destination is attempted independently; a
failure enters the persisted outbox and retries with capped exponential
backoff. Later alerts for that destination queue behind it, preserving `DOWN`
then `RECOVERED` order without holding up healthy destinations. The legacy
`webhook` field remains supported as a destination named `webhook`.

Additional destinations can be routed by check, component, prober, and alert
kind. A destination with no routes receives everything; once any route names a
destination, only matching alerts go there. The log is the always-on `default`
destination and cannot be routed away:

```json
"notification_destinations": [
  {"name":"chat", "webhook":"https://chat.example/hooks/alerts"},
  {"name":"pager", "webhook":"https://pager.example/v1/events",
   "headers":{"Authorization":"Bearer ..."}}
],
"notification_routes": [
  {"name":"chat all", "destination":"chat"},
  {"name":"page public sites", "destination":"pager",
   "checks":["labbookdesigns-www","kilo666-www"], "kinds":["down"]}
],
"escalations": [
  {"name":"unacknowledged public outage", "destination":"pager",
   "after":"10m", "checks":["labbookdesigns-www","kilo666-www"],
   "kinds":["down"]}
]
```

An escalation is queued once when a matching incident is still active,
unsuppressed, and unacknowledged after `after`. Acknowledging or resolving it
before delivery cancels the queued escalation. `GET /v1/deliveries` exposes
the durable outbox; diagnostics include pending age and per-destination errors.

### Observation history

The coordinator journals every accepted scheduled result and every on-demand
corroboration as append-only JSONL. `history_retention` (default 30 days) and
`history_max_per_check` (default 10,000) bound the query window and periodic
atomic compaction. The Ansible deployment stores it at
`/var/lib/parallaxd/observations.jsonl`.

`GET /v1/history?check=svc&since=2026-08-01T00:00:00Z&limit=1000` returns raw
observations with prober/provider, raw outcome, corroborated verdict, latency,
detail, source, and whether the result was suppressed from decision-making.
DNS answers and TLS peer/expiry are extracted into structured fields.
`GET /v1/history/summary` reports the
retained sample counts, availability, average and p95 latency, current DNS
answers, and certificate days remaining; the dashboard renders the same view.

Availability uses scheduled observations only. Corroboration is retained for
incident analysis but excluded from that denominator, because failures fan out
to several probers while healthy checks use one; counting every corroborator
would systematically make outages look several times longer than they were.

Alerts carry the whole verdict, because the strength of the agreement is part
of the finding:

```
DOWN svc (mx.example.com:465) — 3 of 5 probers reported down across 3
providers: contabo, hetzner, netcup; 2 still reported up
```

## Components

A check is how the system finds out; a **component** is what a person cares
about. Nobody outside the fleet wants to know whether `mx-smtps` answered TCP
465 from three vantages — they want to know whether email works.

```json
"components": [
  {
    "name": "email",
    "description": "Sending and receiving mail",
    "checks": ["mx-smtps", "mx-imaps", "mx-submission"]
  },
  {
    "name": "dns",
    "checks": ["ns1", "ns2", "ns3"],
    "down_if": "quorum",
    "down_at": 2
  }
]
```

**A check that belongs to a component does not alert on its own.** The
component alerts once, naming the members that failed:

```
DOWN email — mx-smtps, mx-imaps
```

Otherwise an mx host going down produces one alert per port *plus* one for the
component, which is the noise the grouping exists to remove. A check in no
component is still its own alert, so components are opt-in and adding one to
part of a config does not silence the rest.

Three rollup rules:

| `down_if` | The component is down when |
|---|---|
| `any` (default) | any member check is down — if any part of a service is broken, the service is broken |
| `all` | every member is down — for a pool of equivalent members, one failing is degraded, not an outage |
| `quorum` | `down_at` or more members are down |

The same rule as everywhere else applies to the rollup: **an undecided check is
not evidence.** It cannot make a component down, and it cannot make one up
either — a component is `up` only when every member has been decided and none
is failing. A check that goes quiet holds its component at `unknown` rather
than being silently read as healthy. The exception is a rollup already
satisfied: one failing check under `any` takes the component down whether or
not the others have reported.

## The mesh: telling "I cannot reach this" from "I cannot reach anything"

This is the part that makes parallaxd more than `blackbox_exporter` with a
K-of-N alert rule.

**A partitioned prober is the worst possible reporter.** It cannot reach the
target, it cannot reach its peers to corroborate, and its local view says
everything is down. Corroboration that does not know this turns one broken
uplink into a confident, fleet-wide outage report — worse than the single false
alert it was built to prevent, because it arrives with the authority of a
system that claims to corroborate.

So probers check each other as well as their targets:

```
GET  /v1/peers   probers fetch the fleet list from the coordinator
POST /v1/mesh    probers report which peers they could reach, signed
GET  /v1/mesh    the visibility map
```

The check is a **TCP connect, deliberately not a health check**. The question
is whether the network path works, not whether the peer is happy — a peer whose
store is broken but whose socket answers still proves the reporter has working
connectivity, which is all that is being asked.

The peer list is served by the coordinator rather than configured on each
prober, so there is one authoritative list. Two copies kept in step by hand is
how a prober ends up probing a host decommissioned last month and concluding it
is isolated.

### The rule

A prober is **isolated** when it reached *none* of its peers, having asked at
least two. Its results are then discarded rather than counted — not weak
evidence to be outvoted, but not evidence at all.

**Two peers is a floor, not a default to tune down.** With one peer the
evidence is ambiguous: "I cannot reach my only peer" and "my only peer is down"
are identical observations. Guessing wrong silences a prober that was telling
the truth, and a suppressed prober's outages go unreported — a quiet failure,
which is worse than the noisy one suppression prevents. So it fails open: when
the evidence cannot distinguish the two cases, nothing is suppressed.

Several probers isolated at once is reported as a **partition** rather than as
several host failures, because it points an operator at the network.

### What suppression does and does not do

An isolated prober's result is **not a trigger either**. Fanning out on it would
spend the corroboration budget on reports carrying no information — and during
a partition, when every cut-off prober sees every target as down, that is the
whole budget, starving the triggers that mean something.

An isolated prober's results stop being evaluated until it rejoins. The
coordinator removes that owner from the eligible set and reassigns its checks
to healthy probers; isolation still alerts because the fleet has lost a
vantage and may no longer be able to meet the configured quorum or provider
diversity.

Suppression expires with the report that caused it (`mesh_max_age`, default
3 minutes). Suppression that outlives the partition is indistinguishable from
the outage it was meant to avoid inventing.

Mesh reports are signed like everything else. A report can silence a prober, so
an unauthenticated one is a way to suppress somebody's opinion — which is how a
real outage goes unreported. Identity is bound both ways: one prober cannot
sign a report on another's behalf.

### The by-product

The visibility map is a genuinely useful second output — which parts of the
fleet can see which — and it records asymmetry rather than averaging it away. A
link that works one direction and not the other is a real finding.

`GET /v1/mesh` serves it; `isolated` and `partitioned` also travel in the status
export, because a page claiming corroborated results has to say when the
corroboration is running short.

## The dead-man's switch

A monitoring system's worst failure is not a wrong answer, it is no answer.
Everything above alerts when a check *fails*; without this, nothing alerts when
a check stops *happening* — and silence is indistinguishable from health.

Two mechanisms, deliberately separate. They answer different questions, and
conflating them makes both diagnoses ambiguous.

### Outward: is the coordinator alive?

`parallaxd-watch` receives the heartbeat and alerts when it stops. It ships
with the project rather than pointing at a hosted cron-ping service, because
what the receiver has to be is in a **different failure domain** — different
host, different provider, different uplink — not a different company. A watcher
one provider over catches a dead host, a crashed or wedged process, a bad
deploy, and a provider-wide outage, which between them are essentially every
way a coordinator fails.

The heartbeat has its own Ed25519 protocol domain. The watcher verifies the
coordinator identity, rejects stale and future-dated beats, rejects replays,
and measures silence from authenticated receive time rather than trusting the
sender's clock.

```json
"heartbeat": {"url": "http://watcher.example:8974/v1/heartbeat", "interval": "1m"}
```

The ping is **gated on the coordinator being able to read its own state**, not
on the process still existing. A goroutine that pings on a timer proves only
that the scheduler is running, which is the least interesting way a coordinator
fails; a wedged one still ticks. Building the state document first means the
ping traverses the same locks every verdict traverses, so a coordinator
deadlocked in evaluation stops beating and the external watcher fires.

### Who watches the watcher

Not a third party — each other. The watcher alerts when the coordinator stops
checking in; the coordinator alerts when it can no longer *deliver* there.

| Failure | Reported by |
|---|---|
| coordinator dies or wedges | the watcher, on heartbeat silence |
| the watcher dies | the coordinator, after three failed deliveries |
| both at once | nobody — see below |

A coordinator must not claim to report its own death; that is exactly what it
cannot do. But **"nothing is watching me" is a different fact**, and it is the
only component positioned to know it. Left unreported, a watcher that died
silently means the dead-man's switch is gone with nothing saying so — the same
failure the mechanism exists to remove, one level up. A single failed delivery
is still only logged: one dropped packet is not a dead watcher.

Both dying at once is not covered, and nothing here pretends otherwise. That is
equally true of a hosted service when the alerting path is self-hosted, so it
is a property of the topology rather than a cost of building it yourself.

Starting with no watcher logs a warning rather than defaulting quietly. Running
unwatched is the single point of failure this design has always named, and an
operator should know they are running that way.

### Inward: is anyone still reporting?

A prober that dies quietly takes its checks with it, and those checks simply
stop being evaluated. The coordinator watches for that:

```
stale after = interval × stale_multiplier + stale_grace   (default 3 and 30s)
```

A multiple of the interval rather than a fixed threshold, because a check that
runs every 30 seconds and one that runs hourly have very different ideas of
"late". A check that has never reported counts from process start, so a restart
does not alert on everything at once.

**A stale check becomes `unknown`, never `down`.** Nobody probed the target, so
there is no evidence about it, and calling it down would mean a prober rebooting
pages as an outage of the service it was watching.

Staleness is tracked as a **flag alongside** the last verdict rather than
overwriting it. Two different facts — what was last decided, and whether anyone
is still looking — and collapsing them means a check that was already failing
when its prober died announces itself as a brand new outage when the prober
comes back. Readers see `unknown` either way; `last_known` carries the last
thing actually observed.

Alerts are **grouped by the responsible prober**, because the usual cause is one
prober dying and taking a dozen checks with it:

```
SILENT prober probe-c — no results for 4m30s; these checks are not being run: dns, mail, svc
```

Once, not per tick, and the return transition alerts too — otherwise an operator
is left watching an alert that never closes.

## Status, incidents and maintenance

The coordinator serves a small operational dashboard at `/` and exports the
same state for an off-fleet public status page.

A public status page has to survive the outage it reports, and one served from
the monitored fleet is unavailable in exactly the situation it exists for. That
is a property of where it runs, not of how it is written, so the split is:
the coordinator publishes a document, and something off-fleet — object storage,
a static host — renders it.

```
GET /v1/export              the document
GET /v1/export?signed=true  the same document in a signed envelope
GET /v1/components          just the component view
```

The document carries components, the checks behind them (each with `stale` and
`last_known` so a page can show what nobody is watching), and `generated_at`.
**A renderer must check that timestamp against its own clock.** A page built
from an export the coordinator stopped producing an hour ago shows everything
exactly as it was, which is worse than showing nothing — and staleness is the
one failure a static page cannot detect on its own.

`?signed=true` wraps it in an Ed25519 envelope signed with the coordinator key
probers already verify, so a renderer can check provenance without a second
trust relationship, and the export can be served from storage nobody has to
trust. Verification and interpretation are separate: `wire.OpenDocument`
answers "did the coordinator write this" and hands back raw bytes.

Automatic incident lifecycle is retained durably at `GET /v1/incidents`.
Configured maintenance intervals suppress matching notifications while
retaining a marked incident record at `GET /v1/maintenance`.

### Identity and authorization

parallaxd owns authorization while allowing more than one authentication
method. Local password accounts work in a standalone installation, OpenID
Connect can delegate authentication to any conforming provider, and scoped API
tokens cover automation. All three resolve to the same local role, so changing
identity providers does not change who may operate the fleet.

| Role | Capabilities |
| --- | --- |
| `viewer` | Read the monitor catalogue, revisions, fleet state, and history |
| `operator` | Viewer access plus monitor changes, tests, silences, acknowledgements, and resolutions |
| `admin` | Operator access plus user/token administration, catalogue rollback, and HA promotion |

Passwords are stored as Argon2id hashes. Browser sessions use a Secure,
HttpOnly, SameSite cookie and require a separate CSRF proof for every unsafe
request. User, token, revocation, and session state is persisted with the
coordinator and replicated to the standby; plaintext passwords and API token
secrets are never persisted. A generated API token is shown exactly once.

For a new installation, configure a bootstrap administrator using a secret
file. It is created only if durable state has no users, so leaving this in the
deployment configuration does not reset or recreate the account:

```json
"session_ttl": "12h",
"bootstrap_admin": "admin@example.com",
"bootstrap_password_file": "/etc/parallaxd/keys/bootstrap-password"
```

Local users and service tokens are managed in the dashboard's **Access** view
or under `/v1/auth/users` and `/v1/auth/tokens`. The server refuses to disable,
demote, or delete the last enabled local administrator. When OIDC is enabled,
an account may omit a local password and operate as SSO-only.

```
GET    /v1/auth/me
POST   /v1/auth/login
POST   /v1/auth/logout
POST   /v1/auth/password
GET    /v1/auth/oidc/start
GET    /v1/auth/oidc/callback
GET    /v1/auth/users
POST   /v1/auth/users
PUT    /v1/auth/users/{username}
DELETE /v1/auth/users/{username}
GET    /v1/auth/tokens
POST   /v1/auth/tokens
DELETE /v1/auth/tokens/{id}
```

OIDC users are deliberately pre-provisioned: the configured claim must match a
local username, and the local record supplies the role. Discovery, authorization
code flow, PKCE, state, nonce, ID-token signature, issuer, audience, and expiry
are all verified. An `email` identity must also carry `email_verified: true`;
deployments that deliberately trust an issuer without that claim must opt into
`allow_unverified_email`. `client_secret_file` is optional for public clients:

```json
"oidc": {
  "issuer": "https://id.example.com/application/o/parallaxd/",
  "client_id": "parallaxd",
  "client_secret_file": "/etc/parallaxd/keys/oidc-client-secret",
  "redirect_url": "https://status.example.com/v1/auth/oidc/callback",
  "username_claim": "email",
  "label": "Company sign-in"
}
```

`operator_token_file` remains a migration and break-glass path. Its bearer
credential has administrator privileges but no intrinsic identity, so legacy
requests must still supply `actor`. The dashboard keeps a legacy token only in
the current tab's `sessionStorage`; it is never embedded by the coordinator.
When no users, scoped tokens, or legacy operator token exist, protected API
endpoints return `503` rather than becoming writable by accident.

No authentication method encrypts the connection. Use HTTPS, loopback, an SSH
tunnel, or another encrypted private transport; never send a password, session,
or bearer token over cleartext internet transport. Legacy requests remain
compatible:

```sh
curl -X POST http://127.0.0.1:8972/v1/incidents/7/acknowledge \
  -H "Authorization: Bearer $PARALLAXD_OPERATOR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"actor":"alice","note":"investigating the upstream route"}'

curl -X POST http://127.0.0.1:8972/v1/incidents/7/resolve \
  -H "Authorization: Bearer $PARALLAXD_OPERATOR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"actor":"alice","note":"manually closed after provider confirmation"}'
```

Manual resolution closes the incident record but does not falsify the check's
measured state. The next genuine recovery still moves the check to `up`; a
later down transition opens a new incident.

Operator-created silences are also durable and auditable. They can target
checks, components, or probers; an empty scope is fleet-wide. Cancelling or
expiring a silence immediately delivers any still-active incident it had
suppressed:

```sh
curl -X POST http://127.0.0.1:8972/v1/silences \
  -H "Authorization: Bearer $PARALLAXD_OPERATOR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"mail deploy","ends_at":"2030-01-02T03:04:05Z",\
       "checks":["mx-smtp"],"actor":"alice","comment":"change 1234"}'
```

### Monitor management

The dashboard's **Monitors** view is the live monitor catalogue. Catalogue and
revision reads require at least the viewer role because monitor definitions may
hold sensitive HTTP headers. An operator
can create, edit, clone, disable, or delete a monitor without redeploying the
fleet. The editor validates the complete catalogue before activating a change,
so it rejects unsatisfiable quorums, unknown probers, and changes that would
leave a component referring to a disabled or missing monitor. **Test from all
eligible probers** performs real probes without changing status, history, or
incidents.

`probers` optionally limits a monitor's ownership, failover, and corroboration
to a named pool. An empty list preserves fleet-wide behavior. Use a pool for
private targets so a public prober is never asked to judge a service it cannot
route to:

```json
{
  "name": "internal-prometheus",
  "kind": "http",
  "target": "http://prom.internal:9090",
  "vantage": "internal",
  "prober": "lbc1n3",
  "probers": ["lbc1n3", "dnsc1n2", "backup"],
  "interval": "1m",
  "timeout": "10s",
  "quorum": {"agree": 2, "of": 3}
}
```

Every accepted change is persisted as a full-catalogue revision and replicated
to the warm standby. The **Audit** view records the actor and action and can
atomically roll the catalogue back to any retained revision. The coordinator
keeps the latest 100 revisions. A rollback is itself a new auditable revision;
it does not erase later history.

The relevant API surface is:

```
GET    /v1/monitors
POST   /v1/monitors
PUT    /v1/monitors/{name}
DELETE /v1/monitors/{name}
POST   /v1/monitors/validate
POST   /v1/monitors/test
GET    /v1/monitors/revisions
POST   /v1/monitors/revisions/{id}/rollback
```

The initial catalogue comes from `checks` in the coordinator configuration.
Once runtime state version 5 or later has been written, that durable catalogue is the
source of truth across restarts; changing the static `checks` list alone will
not overwrite operator changes. Use the dashboard/API for subsequent monitor
changes, or deliberately remove/migrate the state file during a controlled
rebootstrap.

For a coordinator bound to loopback, open the control room through a tunnel:

```sh
ssh -L 8972:127.0.0.1:8972 coordinator.example
```

Then browse to `http://127.0.0.1:8972/` and enter the operator name and token.

`GET /v1/diagnostics` explains the current effective and preferred owner of
every check, result-queue pressure, rejected-result counts by reason, and
notification attempts, pending count, oldest queued delivery, and
per-destination errors. It also reports the coordinator's HA role, last
successful replica sync, replication lag, and most recent replication error.
Attempt counters describe the current process;
incidents, silences, and the notification outbox are durable.

### Warm standby coordinator

A standby can continuously copy the primary's decision state, incidents,
silences, pending notification outbox, and observation history. It serves
read-only status while following the primary and does not schedule checks,
accept results, send heartbeats, or deliver alerts. There is deliberately no
automatic election: two coordinators acting at once could duplicate alerts and
make conflicting decisions during a partition.

Configure the primary with a replication token stored outside its JSON:

```json
"ha": {
  "role": "primary",
  "replication_token_file": "/etc/parallaxd/keys/replication-token"
}
```

Configure a host in a different failure domain with durable state and history,
the same replication token, an operator token, and the primary's private
coordinator key:

```json
"state_file": "/var/lib/parallaxd/state.json",
"history_file": "/var/lib/parallaxd/observations.jsonl",
"operator_token_file": "/etc/parallaxd/keys/operator-token",
"ha": {
  "role": "standby",
  "primary_url": "https://primary.internal:8972",
  "replication_token_file": "/etc/parallaxd/keys/replication-token",
  "interval": "30s",
  "timeout": "2m"
}
```

The shared coordinator key is required because probers trust that identity;
the standby must not mint a different one. Copy it through a secret manager or
another audited encrypted channel. Protect the replication path with HTTPS or
a private encrypted network because the bearer token and replicated state are
otherwise visible on the wire.

Failover is an operator procedure:

1. Fence the old primary so it cannot run or accept traffic.
2. Check `GET /v1/ha` on the standby and assess its last sync and any error.
3. Promote it with an authenticated request that explicitly records the
   fencing decision:

   ```sh
   curl -X POST https://standby.internal:8972/v1/ha/promote \
     -H 'Authorization: Bearer OPERATOR_TOKEN' \
     -H 'Content-Type: application/json' \
     -d '{"actor":"alice","confirm_primary_fenced":true}'
   ```

4. Move the coordinator service address (VIP, load balancer, or DNS) to the
   promoted host and verify prober submissions and pending-alert delivery.

Promotion is fsynced before the API reports success and survives restart. It
is intentionally one-way; returning service to the old host means rebuilding
that host as a standby from the current active coordinator. `GET /v1/replica`
is bearer-authenticated and disabled when no replication token is configured.

## Deploying

```sh
cd ansible
ansible-galaxy collection install -r requirements.yml
cp inventory.example inventory   # then edit
ansible-playbook playbook.yml
```

The playbook builds each binary once per distinct target architecture. Each
binary is stamped from the newest commit touching its transitive project
dependencies rather than the repository HEAD, and Go's repository-wide VCS
stamp is disabled. Consequently an unrelated coordinator change leaves the
prober artifact byte-for-byte identical; Ansible's checksum comparison skips
its installation and does not notify the prober restart handler. A second
deployment with no source or configuration changes performs no service
restarts.

Three groups: `parallaxd_coordinator` (exactly one host, and **not** also a
prober — a host that is both means losing it costs a vantage as well as the
decisions), `parallaxd_probers`, and an optional single-host
`parallaxd_standby`. The standby must name a different `parallaxd_provider`
from the primary. It may also be a prober; the deployment keeps its prober and
coordinator signing identities in separate files.
The primary's operator token is copied to the standby through the same
protected path so promotion remains authenticated even when that secret was
originally scoped only to the primary host.

Private agents may additionally join `parallaxd_internal_probers`. Give each a
unique `10.77.0.x` `parallaxd_address`; the play extends its dedicated
`wg-parallaxd` interface to both coordinators while leaving every pre-existing
WireGuard interface untouched. NATed agents initiate both encrypted paths, so
the private site exposes no inbound probe port. Put a restrictive
`parallaxd_allow_targets` list in each private host's gitignored `host_vars`.

**Size the fleet by provider, not by host.** Three probers behind Hetzner are
one opinion held three times, and `distinct_providers` exists to refuse exactly
that. Three probers is the floor — isolation requires having failed to reach at
least two peers, so below three the partition suppression never fires — and
four gives you one spare, so a host in maintenance does not silently drop you
to the floor.

Prober keys are generated **on each host** and the private half never leaves
it. That is the point of per-host keypairs: a compromised control machine
cannot sign as a prober, because it never held the material. The coordinator
standby is the explicit exception: after promotion it must retain the same
identity trusted by the probers, so Ansible copies the primary coordinator key
to a separate standby-only file with secret-bearing tasks marked `no_log`.

When a standby is present, define a random 32-character-or-longer
`parallaxd_replication_token_secret` in the gitignored
`ansible/group_vars/all.yml`. The playbook creates a dedicated
`wg-parallaxd` WireGuard interface between primary and standby; replication
uses that encrypted address and the public coordinator firewall admits replica
traffic only from the tunnel. When internal probers are configured, the same
project-owned interface carries their control traffic. Existing VPN interfaces
are not modified.

The play runs in three passes because the configs are mutually dependent — the
coordinator lists every prober's public key and each prober names the
coordinator's, so neither can be written before both keypairs exist.

### The security model

**Traffic is signed, not encrypted, and the port is restricted by source.**

Ed25519 plus message-specific nonce/timestamp handling gives authenticity,
integrity and replay resistance
end-to-end — and unlike TLS it survives a proxy, because the signature covers
the payload rather than the connection. What it does not give is
confidentiality: an on-path observer sees check names, targets and results.

The answer to that is a firewalld source allowlist rather than a tunnel. The
peer set is small, static and known, so restricting the port to those sources
removes the anonymous attacker entirely — with no key material, no certificate
lifecycle, and no new failure mode in the alerting path. *A monitoring system
that goes blind on a forgotten certificate renewal is a worse trade than one
that leaks its check names to a transit provider.*

> **The allowlist must include the other probers, not just the coordinator.**
> Probers connect to each other for the mesh checks. A rule permitting only the
> coordinator would break every mesh check — and since reaching no peer is how
> isolation is defined, it would silently suppress the entire fleet.

The playbook builds both lists from the inventory so they cannot drift from it.

If a prober ever ends up on a network where the source set is not static, the
allowlist stops working and you need real transport security. Reach for
embedded WireGuard before TLS: no expiry, no CA, and it fails closed rather
than blinding you on a missed renewal.

### One check catalogue

The coordinator owns the check catalogue. `prober:` is a preferred steady-state
owner; probers fetch their current set from `GET /v1/checks`, authenticated with
a short-lived signed credential:

```yaml
parallaxd_checks:
  - name: mx-smtps
    prober: probe-a        # runs it on its own schedule
    kind: tcp
    target: mx.example.com:465
    vantage: public
    interval: 1m
    timeout: 10s
    quorum: {agree: 2, of: 3, distinct_providers: true}
```

`/v1/assignments` and `/v1/status` report who actually runs each check. Omit
`prober:` and rendezvous hashing chooses the preferred owner. If that owner is
silent or isolated, only the affected checks move to healthy probers.

The coordinator's `fan_out_timeout` must be at least one second longer than
every check that needs corroboration. A hard-down target may consume the full
check timeout before producing its `down` result; the remaining time is the
budget for returning and verifying that signed vote. Invalid combinations fail
at startup instead of becoming silently inconclusive during an outage.

Validate a candidate without starting listeners, restoring state, or sending
traffic:

```sh
parallaxd -config /etc/parallaxd/coordinator.json.candidate -validate
```

Validation uses the same parser, key loading, and coordinator construction as
startup. It rejects unknown JSON fields, trailing documents, duplicate names
or prober keys, impossible quorums/provider diversity, invalid assignments,
maintenance windows, check options, and unsafe timeout budgets. The Ansible
deployment renders to a temporary path, runs this preflight with the newly
installed binary, and only then atomically replaces the live configuration.

Also worth setting on any prober that can route into a LAN: `allow_targets`.
It defaults to empty, meaning "anywhere the built-in and vantage rules permit",
which is right for a prober on a public network and wrong for one inside.

## Prior art

[`rippleFCL/meshmon`](https://github.com/rippleFCL/meshmon) is the closest
thing and establishes that the premise works: nodes exchange evidence and
webhooks fire on consensus. **Don't build the naive version of this — it
exists.**

It differs in ways that decided this design: it is continuous rather than
on-demand, which caps it at HTTP and ping probes; it is peer-to-peer with
leader election; and it does not address partition suppression, vantage
classes, or provider-diverse corroborator selection.

If those three differentiators are ever dropped from the plan, use meshmon
instead of finishing this.

## Building

```sh
go build ./...
go test -race ./...
```

## License

MIT
