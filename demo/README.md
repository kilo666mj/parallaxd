# Single-host demo

This Compose stack demonstrates parallaxd's dashboard, signed coordinator and
prober traffic, dynamic assignment, corroborated failure, recovery, mesh
reporting, and watcher heartbeat on one Docker host.

It is **not a production topology**. The three provider names are illustrative:
all containers share one host, kernel, Docker network, power source, and network
path. The watcher also dies with the host it watches. Do not interpret this
stack as independent availability evidence or reuse its public demo keys and
password.

From the repository root:

```sh
docker compose up --build --wait
```

Open <http://127.0.0.1:8972> and sign in with:

- Username: `demo-admin`
- Password: `demo-only-change-me`

The `demo-web` monitor should become `up`. Exercise corroboration and recovery:

```sh
docker compose pause demo-target
# Wait roughly 10 seconds and observe one corroborated down transition.
docker compose unpause demo-target
# Observe one recovered transition after the next scheduled check.
```

Pause is intentional: stopping the container removes its Docker DNS answer, so
the probers correctly return `unknown` instead of claiming the target is down.
Pausing retains the address while making the service unreachable.

Stopping `probe-a` demonstrates reassignment to a remaining healthy prober:

```sh
docker compose stop probe-a
docker compose start probe-a
```

Logs contain the demo's alert transitions because no external webhook is
configured:

```sh
docker compose logs -f coordinator watcher
```

Remove the stack and its persisted coordinator state to reset the demo:

```sh
docker compose down -v
```
