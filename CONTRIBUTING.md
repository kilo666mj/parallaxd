# Contributing

Issues and pull requests are welcome. For security reports, follow
[`SECURITY.md`](SECURITY.md) instead of opening a public issue.

## Development

Install the Go version declared in [`go.mod`](go.mod), then run:

```sh
go test -race ./...
go vet ./...
gofmt -w path/to/changed.go
go mod tidy
ansible/scripts/test-component-version.sh
```

Keep commits focused and include tests for behavior changes. Public examples
must use reserved domains (`example.com`, `example.net`, or `example.org`) and
documentation address ranges. Do not commit real inventories, host variables,
tokens, webhooks, private keys, internal names, or operational drill records.

Pull requests should explain the problem, the chosen behavior, operational or
security implications, and how the change was verified.
