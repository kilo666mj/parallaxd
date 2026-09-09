#!/usr/bin/env python3
"""Read-only local assurance checks. Emit a redacted JSON report; fail closed.

Run on each coordinator and watcher using its existing config. No service or
monitor mutations, notification sends, proxy environment, or redirects.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def age(value, now):
    stamp = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    seconds = (now - stamp).total_seconds()
    if seconds < -60:
        raise ValueError("timestamp is in the future")
    return seconds


def inspect_coordinator(get, cfg, now, previous):
    failures = []
    d = get("/v1/diagnostics")
    if age(d["generated_at"], now) > 120:
        failures.append("stale diagnostics")
    ha = d["ha"]
    role = cfg.get("ha", {}).get("role", "primary")
    if ha["role"] != role:
        failures.append("HA role differs from configuration")
    if role == "standby":
        if ha["active"] or ha["promoted"]:
            failures.append("standby is active/promoted; reconcile host roles")
        if age(ha["last_replica_sync"], now) > 120:
            failures.append("replication sync older than two minutes")
        if not 0 <= ha.get("replication_lag_ms", 0) <= 120000:
            failures.append("replication lag outside recovery objective")
        if ha.get("last_replication_error"):
            failures.append("replication reports an error")
    elif not ha["active"]:
        failures.append("primary is inactive")
    if d["result_queue"]["depth"]:
        failures.append("result queue is nonempty")
    if d["notifications"]["pending"]:
        failures.append("notification queue is nonempty")
    if d["notifications"].get("last_error") or any(
        dest.get("last_error")
        for dest in d["notifications"].get("destinations", {}).values()
    ):
        failures.append("notification delivery reports an error")
    if d["history"].get("last_error"):
        failures.append("history persistence reports an error")
    rejected = d.get("rejected_results") or {}
    for reason, count in rejected.items():
        if previous is not None and count > previous.get(reason, 0):
            failures.append("result rejection counters increased")
            break
    if role == "primary":
        mesh = get("/v1/mesh")
        expected = {p["name"] for p in cfg["probers"]}
        if expected - set(mesh.get("Reporting") or []):
            failures.append("one or more configured probers lack fresh mesh reports")
        if mesh.get("Isolated") or mesh.get("Partitioned"):
            failures.append("fleet reports isolation or partition")
        if any(not a.get("effective_owner") for a in d["assignments"]):
            failures.append("a monitor has no eligible active owner")
        if any(s.get("stale") for s in get("/v1/status")):
            failures.append("one or more monitors lack fresh observations")
    return failures, rejected


def inspect_watcher(get, now, max_silence):
    state = get("/v1/status")
    if not state["alive"] or age(state["last"]["at"], now) > max_silence:
        return ["watcher lacks a fresh authenticated heartbeat"]
    return []


def atomic_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix=".operations-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(report, f)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--kind", choices=("coordinator", "watcher"), required=True)
    parser.add_argument("--token-file", type=Path, help="dedicated viewer token override")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--max-heartbeat-age", type=int, default=120)
    parser.add_argument("--mcp", action="store_true", help="also initialize MCP and call its read-only status tool")
    args = parser.parse_args()
    now = dt.datetime.now(dt.timezone.utc)
    report = {"at": now.isoformat(), "ok": False, "failures": []}
    try:
        cfg = json.loads(args.config.read_text())
        listen = cfg["listen"]
        host, port = listen.rsplit(":", 1)
        if host in ("", "0.0.0.0", "[::]"):
            host = "127.0.0.1"
        base = "http://" + host + ":" + str(int(port))
        token_path = args.token_file or cfg.get("operator_token_file")
        token = Path(token_path).read_text().strip() if token_path else ""
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect()
        )

        def request(path, payload=None):
            headers = {"Authorization": "Bearer " + token} if token else {}
            data = None
            if payload is not None:
                headers.update({"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
                data = json.dumps(payload).encode()
            req = urllib.request.Request(base + path, headers=headers, data=data)
            with opener.open(req, timeout=15) as response:
                body = response.read((4 << 20) + 1)
                if len(body) > 4 << 20:
                    raise ValueError("oversize response")
                if response.headers.get_content_type() == "text/event-stream":
                    body = b"\n".join(line[5:].lstrip() for line in body.splitlines() if line.startswith(b"data:"))
                return json.loads(body)

        previous = None
        if args.report.exists():
            previous = json.loads(args.report.read_text()).get("rejected_results")
            if previous is not None:
                report["rejected_results"] = previous
        if args.kind == "coordinator":
            failures, rejected = inspect_coordinator(request, cfg, now, previous)
            report["rejected_results"] = rejected
        else:
            failures = inspect_watcher(request, now, args.max_heartbeat_age)
        # The standby rejects POST, including MCP's read-only JSON-RPC calls.
        if args.mcp and cfg.get("ha", {}).get("role", "primary") == "primary":
            init = request("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-03-26", "capabilities": {},
                "clientInfo": {"name": "parallaxd-operations", "version": "1"}}})
            if "result" not in init:
                failures.append("MCP initialization failed")
            else:
                result = request("/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                         "params": {"name": "parallaxd_get_status", "arguments": {}}})
                if "result" not in result or result["result"].get("isError"):
                    failures.append("MCP status tool failed")
        report.update(ok=not failures, failures=failures)
    except Exception as exc:
        # Never echo HTTP response bodies, URLs, config values, or credentials.
        report["failures"].append("assurance check failed: " + type(exc).__name__)
    atomic_report(args.report, report)
    print(json.dumps(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
