# mde-lr Roadmap

Status: Active  
Owner: mde-lr maintainers  
Last updated: 2026-02-16

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

- Live Response coverage is implemented and tested:
  - `GetFile`
  - `RunScript`
  - `PutFile`
- Strong foundation already exists:
  - OAuth2 token provider with caching/expiry buffer
  - Authenticated client with one-shot 401 refresh retry
  - Typed error model (`MdeError`) preserving API status/body
  - Unit + integration tests with wiremock
- Gaps before broad API expansion:
  - Client surface lacks `PATCH`, `DELETE`, and multipart upload support.
  - No standardized structured observability layer yet.
  - Endpoint coverage tracking is manual today.

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

## Milestone 0: Foundation for Expansion

Deliverables:

- Introduce core HTTP capabilities needed for full API coverage:
  - `PATCH`
  - `DELETE`
  - multipart/form-data upload
  - explicit empty-response (`204`) handling
- Add configurable retry policy primitives for non-auth failures
  (starting with `429` handling).
- Define endpoint manifest schema and create initial inventory file.
- Establish codegen boundary (what is generated vs handwritten).

Exit criteria:

- New client methods are covered by unit and integration tests.
- No regression in existing Live Response flow tests.
- Manifest exists and is validated in CI.
- Documentation explains generation and extension workflow.

## Milestone 1: Core Incident Response API Families

Deliverables:

- Add machine and machine-action families beyond live response:
  - device lookup/list/get
  - isolate/unisolate
  - AV scan
  - collect investigation package
  - stop and quarantine file
  - restrict/unrestrict code execution
- Reuse shared action-polling abstractions where applicable.
- Ensure permission mapping is documented per operation.

Exit criteria:

- Public APIs for these families are documented and tested.
- CLI can exercise representative operations end-to-end.
- Errors include operation identifiers (for example action IDs) when available.

## Milestone 2: Library + Alert Workflows

Deliverables:

- Script/library management family:
  - list/upload/delete library files
- Alert workflows:
  - list/get/update alerts
- Shared OData query helper for list endpoints.

Exit criteria:

- Multipart upload and delete paths are stable in integration tests.
- Alert update semantics are validated with failure-path tests.
- Documentation includes permission prerequisites and concrete examples.

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

1. Implement Milestone 0 client-surface upgrades (`PATCH`, `DELETE`,
   multipart, `204` handling).
2. Add endpoint manifest + CI validation scaffold.
3. Audit and correct Live Response `PutFile` parameter contract against current
   MDE docs to ensure API fidelity before broad rollout.
