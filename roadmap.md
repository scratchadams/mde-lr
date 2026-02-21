# mde-lr Roadmap

Status: Active  
Owner: mde-lr maintainers  
Last updated: 2026-02-20

## 1. Goal

Evolve `mde-lr` from a Live Response-focused CLI/library into a reusable Rust
crate ecosystem that can cover the broad Microsoft Defender for Endpoint (MDE)
API surface while preserving correctness, clarity, and operational
troubleshootability.

## 2. Guiding Principles

These principles are aligned with `AGENTS.md`, `CLAUDE.md`, and
`architecture.md`:

- Understand invariants before changing boundaries.
- Keep transport concerns separate from endpoint-domain logic.
- Prefer small, verifiable, reversible increments.
- Require tests and docs for each new public behavior.
- Treat observability as a first-class value: errors, retries, and timeouts
  must be diagnosable with concrete context.

## 3. Current Baseline

Through Milestone 2, the following is implemented and tested (147 tests, 21/32 endpoints):

- **Live Response** — GetFile, RunScript, PutFile (4-step async flow)
- **Machines** — list (OData filter), get, update (tags/device value)
- **Machine Actions** — isolate, unisolate, AV scan, collect investigation package, stop and quarantine file, restrict/unrestrict code execution
- **Library** — list, upload (multipart), delete library files
- **Alerts** — list (OData filter), get, update, batch-update security alerts
- **Foundation** — OAuth2 token provider, authenticated client (401/429 retry), typed errors, PATCH/DELETE/multipart, endpoint manifest with CI validation
- **CLI** — 21 action flags covering all implemented endpoints

Remaining gaps:
- No structured logging/tracing (`tracing` crate) — observability is print-based.
- Results are fully buffered in memory before writing to disk.
- Endpoint coverage at 66% (21/32 in manifest).

## 4. Target Architecture

- Workspace split:
  - `mde-client` (core auth/client/error/shared models)
  - endpoint-domain crates (for example: `mde-live-response`, `mde-machines`,
    `mde-alerts`, etc.)
  - `mde-lr` CLI crate as a thin consumer of library crates
- Hybrid endpoint implementation model:
  - Core transport/auth/error stays handwritten.
  - Endpoint inventory is captured in a curated manifest.
  - Repetitive endpoint boilerplate is generated from the manifest.
  - CI validates manifest claims against upstream MDE docs.

## 5. Delivery Plan

## Milestone 0: Foundation for Expansion (Complete)

Deliverables (all done):

- [x] PATCH, DELETE, multipart/form-data upload, 204 No Content handling
- [x] Configurable retry policy (429 with `Retry-After` header)
- [x] Endpoint manifest schema + CI validation
- [x] Codegen boundary definition

## Milestone 1: Core Incident Response API Families (Complete)

Deliverables (all done):

- [x] Extracted shared action-polling abstraction (`action.rs` — `ActionStatus`, `MachineAction`, `PollConfig`, `poll_action()`)
- [x] Machines family: `list_machines()` (OData filter), `get_machine()`, `update_machine()` with `Machine` struct (17 fields) and `ODataList<T>` generic wrapper
- [x] Machine Actions family: 7 endpoints (isolate, unisolate, AV scan, collect investigation package, stop and quarantine file, restrict/unrestrict code execution) with shared `post_and_poll()` helper
- [x] CLI integration: 9 new flags (`--isolate`, `--unisolate`, `--scan`, `--collect-investigation`, `--stop-quarantine`, `--restrict-execution`, `--unrestrict-execution`, `--get-machine`, `--list-machines`) plus `--comment`, `--isolation-type`, `--scan-type`, `--sha1`, `--filter`
- [x] 24 new integration tests + 24 new unit tests (113 total)
- [x] Manifest updated: 14/32 endpoints implemented
- [x] Permission mapping documented per operation in module docs

## Milestone 2: Library + Alert Workflows (Complete)

Deliverables (all done):

- [x] Library family: `list_library_files()`, `upload_library_file()` (multipart), `delete_library_file()` (204 No Content) with `LibraryFile` struct (8 fields)
- [x] Alerts family: `list_alerts()` (OData filter), `get_alert()`, `update_alert()` (PATCH), `batch_update_alerts()` (PATCH, empty response) with `Alert` struct (~30 fields), `AlertComment`, `UpdateAlertRequest`, `BatchUpdateAlertsRequest`
- [x] `patch_no_content()` client method for PATCH endpoints with JSON body but empty response
- [x] CLI: 8 new action flags (`--list-library`, `--upload-library`, `--delete-library`, `--list-alerts`, `--get-alert`, `--update-alert`, `--batch-update-alerts`) + 7 supporting params (`--description`, `--alert-id`, `--alert-ids`, `--status`, `--classification`, `--determination`, `--assigned-to`)
- [x] 12 new integration tests (5 library + 7 alerts) + 22 new unit tests (4 library + 9 alerts + 10 CLI parse - 1 conflict test)
- [x] Manifest updated: 21/32 endpoints implemented (66%)
- [x] Test coverage: 147 total (111 unit + 36 integration)
- [x] Permission mapping documented per operation in module docs

## Milestone 3: Hunting + Indicators

Deliverables:

- Advanced hunting query support.
- Indicator CRUD and bulk operations.
- JSON-first output path for automation consumers.

Exit criteria:

- Query and indicator flows are covered by integration tests.
- CLI and library examples demonstrate automation-friendly usage.
- Error diagnostics remain structured and actionable.

## Milestone 4: Broad Coverage Rollout

Deliverables:

- Expand to remaining high-value families (vulnerabilities, software,
  recommendations, score, investigations, related-entity lookups).
- Use manifest + codegen pipeline to keep pace with endpoint growth.

Exit criteria:

- Coverage report is generated in CI and tracked over time.
- Public docs clearly distinguish implemented vs planned endpoint families.

## 6. Observability Workstream (Cross-Cutting)

This applies to every milestone:

- Add structured tracing around API request lifecycle:
  - method/path
  - status code
  - latency
  - retry attempts and retry reasons
  - timeout path
  - known operation identifiers (for example `action_id`)
- Keep secrets/tokens out of logs.
- Ensure tests validate diagnostic quality for failure paths, not only success
  paths.
- Produce troubleshooting docs for common classes of failure:
  - permission/role mismatch
  - throttling (`429`)
  - action terminal failures
  - malformed/changed response payloads

## 7. Quality Gates

All milestones must meet:

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`
- Updated docs for public API changes
- Added tests for new behavior and failure paths
- Architecture notes updated for any boundary or invariant change

## 8. Known Risks and Mitigations

- Upstream API/document drift:
  - Mitigation: manifest validation + periodic contract smoke checks.
- Inconsistent endpoint shapes across API families:
  - Mitigation: keep generated layers thin; preserve handwritten overrides.
- Scope expansion outruns maintainability:
  - Mitigation: enforce milestone exit criteria and avoid parallel major
    rewrites.

## 9. Immediate Next Actions

1. Implement Milestone 3: Advanced hunting query support and indicator CRUD.
2. Add JSON-first output path for automation consumers.
3. Consider extracting shared OData query helper for list endpoints.
4. Update manifest to track new endpoints as implemented.
