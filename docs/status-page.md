# Public status page

`parallaxd-status` turns the coordinator's signed export into a static
`index.html`. Each run fetches `/v1/export?signed=true`, verifies the Ed25519
signature with the coordinator's public key, keeps only the checks and
components listed in its configuration, and atomically replaces the page.

A status page has to stay up during the outage it reports, so serve the output
from somewhere that does not share the monitored fleet's failure modes:
object storage, a static host such as Cloudflare Pages, or a web server behind
a tunnel with a connector on more than one host.

## What it publishes

- Only the checks and components named in `groups`. The export contains every
  check name, including internal ones; the page never copies the export.
- Each item's status (Operational, Degraded, Outage or Unknown) and 30-day
  uptime from the coordinator's [uptime report](operations.md#uptime).
- An overall banner: all operational, degraded, partial or major outage.
- Public [status notices](operations.md#status-notices): open incidents and
  announced maintenance above the services, and notices resolved in the last
  week in a collapsed list below them. A notice names only the affected items
  that the page lists.

Notices are written by operators and never change the corroborated statuses or
the banner, so a page can show "Monitoring" on an incident while every check
is Operational.

A check the coordinator marks stale is shown as Unknown. If the export is older
than `max_age` when the page is rendered, every item is shown as Unknown and
the banner says the data is out of date. The page also compares the export's
time with the reader's clock and shows a warning when the page itself stops
being updated. It reloads every 60 seconds.

If fetching or verification fails, the command exits non-zero and leaves the
previous page in place, so the reader-side staleness warning takes over.

## Configuration

```json
{
  "source": "http://127.0.0.1:8972/v1/export?signed=true",
  "coordinator_name": "coordinator",
  "coordinator_key": "BASE64-COORDINATOR-PUBLIC-KEY",
  "output_dir": "/var/www/status",
  "title": "Example status",
  "logo_url": "https://example.com/logo.svg",
  "max_age": "5m",
  "groups": [
    {
      "name": "Websites",
      "items": [
        { "check": "website", "label": "www.example.com" },
        { "component": "mail", "label": "Email" }
      ]
    }
  ]
}
```

- `source` is an http(s) URL or a local file containing the signed export. The
  export endpoint does not need a token, but the coordinator port is
  allowlisted, so run the renderer on a host that can reach it, such as a
  coordinator or prober.
- `coordinator_name` and `coordinator_key` are the same values probers and the
  watcher use (`coordinator_key` in their configuration).
- Each item names exactly one `check` or `component`; `label` is the public
  name. Names missing from the export are shown as Unknown and reported on
  stderr.

## Ansible

[`ansible/status-page.yml`](../ansible/status-page.yml) installs the renderer
and a one-minute timer on the hosts in the `parallaxd_status_page` group. Set
`parallaxd_status_binary` (a local `parallaxd-status` build for the host's
architecture) and `parallaxd_status_config` (the configuration above without
`output_dir`) in your inventory. To publish to object storage, also set
`parallaxd_status_upload` with `url` (the object URL, for example
`https://<account>.r2.cloudflarestorage.com/<bucket>/index.html`),
`access_key_id` and `secret_access_key`. After each render, curl uploads the
page with an S3 signature and a 30-second `Cache-Control`. The credentials reach
curl through a systemd credential, not the command line. For Cloudflare R2, the
secret access key is the SHA-256 hex digest of the API token value.

## Running on a timer

```ini
# /etc/systemd/system/parallaxd-status.service
[Unit]
Description=Render the parallaxd status page

[Service]
Type=oneshot
ExecStart=/usr/local/bin/parallaxd-status -config /etc/parallaxd-status/status.json
# A user that owns /var/www/status; the web server only needs to read it.
User=parallaxd-status

# /etc/systemd/system/parallaxd-status.timer
[Unit]
Description=Render the parallaxd status page every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
```

To publish somewhere other than a local web root, add a second `ExecStart`
that uploads the directory, for example with `rclone sync` to object storage or
`wrangler pages deploy`. A `max_age` of a few times the timer interval avoids
false staleness warnings.
