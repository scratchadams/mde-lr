# CLAUDE.md

## Project Overview

**mde-lr** is an async Rust CLI client and library for Microsoft Defender for Endpoint (MDE). It authenticates via Azure AD OAuth2 (client credentials flow) and orchestrates remote actions on managed devices: Live Response operations (GetFile, RunScript, PutFile), machine queries (list, get, update), incident response actions (isolate, scan, quarantine, restrict execution), library file management (list, upload, delete), and alert triage workflows (list, get, update, batch-update).

## Build & Run

```bash
# Requires Rust 1.88.0 (edition 2024). Toolchain pinned in rust-toolchain.toml.
cargo build

# Live Response actions
cargo run -- --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> -g --file <PATH>
cargo run -- --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> -r --script <NAME> [--args <ARGS>]
cargo run -- --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> -p --file <PATH>

# Machine actions (incident response)
cargo run -- --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> --isolate --comment "reason"
cargo run -- --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> --scan --comment "reason"

# Machine queries
cargo run -- --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> --get-machine
cargo run -- --tenant-id <TID> --client-id <CID> --secret <S> --list-machines [--filter "expr"]

# Library management
cargo run -- --tenant-id <TID> --client-id <CID> --secret <S> --list-library
cargo run -- --tenant-id <TID> --client-id <CID> --secret <S> --upload-library --file ./script.ps1 --description "desc"
cargo run -- --tenant-id <TID> --client-id <CID> --secret <S> --delete-library --file "script.ps1"

# Alert workflows
cargo run -- --tenant-id <TID> --client-id <CID> --secret <S> --list-alerts [--filter "severity eq 'High'"]
cargo run -- --tenant-id <TID> --client-id <CID> --secret <S> --get-alert --alert-id <ID>
cargo run -- --tenant-id <TID> --client-id <CID> --secret <S> --update-alert --alert-id <ID> --status Resolved
cargo run -- --tenant-id <TID> --client-id <CID> --secret <S> --batch-update-alerts --alert-ids "a1,a2" --status Resolved

# Run all tests (111 unit + 36 integration = 147 total)
cargo test

# Lint and format
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

## Project Structure

```
src/
  lib.rs              # Crate root — re-exports modules, #![warn(missing_docs)]
  main.rs             # CLI entry point (clap-derived args, exit codes)
  auth.rs             # OAuth2 TokenProvider — token acquisition, caching, expiry
  client.rs           # MdeClient — authenticated HTTP wrapper with 401/429 retry
  error.rs            # MdeError — typed error hierarchy (thiserror)
  action.rs           # Shared action-polling abstraction (ActionStatus, MachineAction, PollConfig)
  live_response.rs    # Live Response models + 4-step orchestration
  machines.rs         # Machines family — list, get, update endpoints
  machine_actions.rs  # Machine Actions family — isolate, scan, quarantine, etc.
  library.rs          # Library family — list, upload, delete library files
  alerts.rs           # Alerts family — list, get, update, batch-update alerts
tests/
  live_response_flow.rs    # Integration tests for live response flow
  machines_flow.rs         # Integration tests for machines endpoints
  machine_actions_flow.rs  # Integration tests for machine action endpoints
  library_flow.rs          # Integration tests for library endpoints
  alerts_flow.rs           # Integration tests for alert endpoints
  manifest_validation.rs   # Endpoint manifest TOML validation
manifest/
  endpoints.toml           # MDE API endpoint inventory (21/32 implemented)
```

## Architecture

Five endpoint families share a common transport layer:

- **Live Response** — 4-step async pipeline: POST → poll → download link → SAS download
- **Machines** — GET/PATCH endpoints for device lookup, listing (OData), and updates
- **Machine Actions** — POST → optional poll pattern for isolate, scan, quarantine, etc.
- **Library** — List/upload (multipart)/delete for Live Response library files
- **Alerts** — List (OData filter)/get/update (PATCH)/batch-update for security alerts

Key design decisions:
- `MdeClient.auth` uses `tokio::sync::Mutex` so `&self` methods can lazily refresh the token
- `base_url` is configurable for sovereign clouds and test overrides
- Token endpoint URL is configurable via `TokenProvider::with_token_url()`
- All endpoint functions are free functions borrowing `&MdeClient`, not methods
- `ActionStatus::Unknown` with `#[serde(other)]` for forward-compatible API parsing
- `poll_action()` in `action.rs` is the shared polling abstraction for all action families
- `ODataList<T>` generic wrapper for collection responses (reusable across list endpoints)

## Conventions

- **Error type**: `MdeError` (typed enum via thiserror) with variants: `Auth`, `Api`, `Timeout`, `ActionFailed`, `Throttled`, `Parse`, `Network`
- **Serde**: PascalCase field renaming for MDE API contract fidelity (`#[serde(rename = "Commands")]`)
- **Comments**: Explain "why," not "what" — per AGENTS.md
- **Docs**: `#![warn(missing_docs)]` enforced on all public items
- **Testing**: Every public function has tests; tests encode semantics, not implementation
- **Observability**: Networked flows should emit actionable context (endpoint,
  method, status, retry/timeout signals, and operation identifiers such as
  action ID when available) so failures are diagnosable in both runtime logs
  and tests.
- **No panics** in production paths; early returns with `?`
- **Async/await** everywhere via Tokio; no blocking calls

## Testing

- **Unit tests** are embedded in each module (`auth.rs`, `client.rs`, `error.rs`, `action.rs`, `live_response.rs`, `machines.rs`, `machine_actions.rs`, `library.rs`, `alerts.rs`, `main.rs`)
- **Integration tests** in `tests/` use `wiremock` to mock both MDE API and SAS download endpoints
- Test helpers: `TokenProvider::with_token()` bypasses Azure AD, `MdeClient::with_base_url()` redirects to mock server
- 147 total tests: 111 unit + 36 integration

## Dependencies

| Crate | Purpose |
|-------|---------|
| `clap` (derive, env) | CLI argument parsing with env var support |
| `reqwest` (json, form, multipart) | Async HTTP client |
| `serde` / `serde_json` | JSON serialization |
| `serde_urlencoded` | Form-encoded serialization for token requests |
| `thiserror` | Typed error derivation |
| `tokio` (full) | Async runtime |
| `bytes` | Byte buffer handling |
| `toml` (dev) | TOML deserialization for manifest validation |
| `wiremock` (dev) | HTTP mocking for tests |

## PR Checklist

Per PR or phase update, require:
- Short "Why" statement (2-3 sentences explaining the motivation)
- Tests added for new behavior
- Any public API changes documented
- Explicit failure-path notes when control-flow types change (`ActionStatus`, `MdeError`)
