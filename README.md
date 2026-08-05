# parallaxd

Corroborated availability monitoring: check from one place, confirm from
several, alert only when they agree.

Parallax is the apparent shift of an object viewed from two separated points,
and the method by which its distance is established. That is the idea here — a
single viewpoint cannot establish the fact, separated viewpoints can.

> **Status: early but complete end to end.** Both binaries build, run, and have
> been smoke-tested together: a real outage produces exactly one alert and a
> recovery produces one more. Not deployed anywhere yet, and probers still take
> their check list from their own config rather than from the coordinator.

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

Peer-to-peer sounds better and is where these projects die — leader election,
split brain, and eventually a worse Raft. A coordinator being down is a
monitoring gap rather than an outage: probers keep probing and nothing alerts.
That is what [the dead-man's switch](#the-dead-mans-switch) exists to make
noticeable.

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
- **Nonces and expiry on requests**, so a result answers only the request it was
  produced for and a captured request is not replayable forever.
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

A first-ever `up` is not a recovery either. Announcing "recovered" for
everything at startup is the other way a monitoring channel gets muted.

Assignment is computed rather than configured — rendezvous hashing over check
name and prober name, so adding a prober moves only the checks that should
move, instead of reshuffling every check to a different vantage. `GET
/v1/assignments` exposes it; `GET /v1/status` shows the current verdict per
check.

### Alerting

A `Notifier` interface with two generic implementations: a log, and a webhook
that POSTs the alert as JSON. Anything that knows about a particular chat
product or monitoring system belongs outside this repository — parallaxd should
be useful to someone running none of the same infrastructure, and the webhook is
where their own glue attaches.

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

## The dead-man's switch

A monitoring system's worst failure is not a wrong answer, it is no answer.
Everything above alerts when a check *fails*; without this, nothing alerts when
a check stops *happening* — and silence is indistinguishable from health.

Two mechanisms, deliberately separate. They answer different questions, and
conflating them makes both diagnoses ambiguous.

### Outward: is the coordinator alive?

```json
"heartbeat": {
  "url": "https://hc-ping.example/uuid",
  "interval": "1m",
  "headers": {"Authorization": "Bearer ..."}
}
```

The coordinator POSTs to that URL on every interval. If it dies, the pings stop
and the external service alerts. **The URL must point off the fleet** — a
watcher inside it cannot report the fleet being unreachable, which is exactly
the case that matters.

The ping is **gated on the coordinator being able to read its own state**, not
on the process still existing. A goroutine that pings on a timer proves only
that the scheduler is running, which is the least interesting way a coordinator
fails; a wedged one still ticks. Building the state document first means the
ping traverses the same locks every verdict traverses, so a coordinator
deadlocked in evaluation stops beating and the external watcher fires.

A failed ping is logged, never alerted. A coordinator that alerted about its own
heartbeat would be claiming to report on its own death.

Starting without a heartbeat URL logs a warning rather than defaulting quietly.
Running with no external watcher is the single point of failure this design has
always named, and an operator should know they are running that way.

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

## Status export

parallaxd exports the state a status page is built from. **It does not host
one.**

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

What deliberately stays out: incident lifecycle, human-written updates,
maintenance windows, subscriber notification. The value of those is that a
person wrote them, and generating them from probe verdicts produces a worse
page than none — flapping components, protocol jargon, no context.

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
