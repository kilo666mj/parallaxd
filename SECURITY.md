# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature for this
repository. Do not open a public issue with exploit details, credentials, or
production topology.

Include the affected version or commit, reproduction steps, impact, and any
suggested mitigation. You should receive an acknowledgement within seven days.

## Supported versions

Until versioned releases are published, only the current `main` branch receives
security fixes. Operators should follow the weekly vulnerability-check and
upgrade process in [`docs/operations.md`](docs/operations.md).

## Deployment boundary

Control traffic is authenticated and integrity-protected but is not inherently
confidential. Use the `parallaxd-network` WireGuard enrollment workflow or an
equivalent encrypted private transport; source firewalling alone is not
confidentiality. Keep key files, webhook URLs, bootstrap
passwords, replication tokens, OIDC secrets, inventories, and host variables
outside the repository.
