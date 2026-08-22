# Issue #237: contiguous CLI tenant scope

## Contract

CLI tenant targeting now closes resolved org/project/environment dimensions into
one validated `TenantScope`: instance, org, project, or environment. Project
without org and environment without project return `ExitUsage`; access routing
cannot inspect or silently discard a sparse child dimension.

Resolution precedence remains flag, environment variable, project pin, then
selected context, independently per dimension. A higher-precedence child may
inherit missing parents from authoritative lower-precedence selections, but the
assembled result must be contiguous before access builds a route. Explicit
`--instance-scope` continues to override implicit tenant selections and still
conflicts with explicit `--org`, `--project`, or `--env` flags.

## Compatibility

Instance, org, project, and environment access route bytes are unchanged. No
server authorization, API, database, migration, or generated output changed.

## Validation

- `go test -count=1 ./internal/cli/... -run 'Scope|Access|Resolve'`: 26 passed
- `go test -count=1 ./internal/cli/...`: 259 passed
- `go test -count=1 ./internal/isolation/`: 1,092 passed
- `go vet ./internal/cli/...`: passed
- `go build ./...`: passed
- `go test -count=1 ./...`: 3,259 passed in 57 packages
