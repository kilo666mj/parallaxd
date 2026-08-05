# parallaxd

Corroborated availability monitoring: check from one place, confirm from
several, alert only when they agree.

Parallax is the apparent shift of an object viewed from two separated points,
and the method by which its distance is established. That is the idea here — a
single viewpoint cannot establish the fact, separated viewpoints can.

> **Status: early.** The check model and the probers work and are tested. The
> coordinator, quorum, transport and alerting are not written. Nothing is
> deployed.

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

## Architecture

A coordinator with probers, not peer-to-peer consensus.

| Binary | Role |
|---|---|
| `parallaxd` | coordinator: assigns checks, requests corroboration, applies quorum, owns alerting and deduplication |
| `parallaxd-probe` | prober: runs checks, answers corroboration requests, **decides nothing** |

Peer-to-peer sounds better and is where these projects die — leader election,
split brain, and eventually a worse Raft. A coordinator being down is a
monitoring gap rather than an outage: probers keep probing and nothing alerts.
That needs a dead-man's switch, which has to be answered deliberately rather
than by accident.

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
