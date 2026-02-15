# CLAUDE.md

## Project Overview

**mde-lr** is an async Rust CLI client and library for Microsoft Defender for Endpoint (MDE) Live Response. It authenticates via Azure AD OAuth2 (client credentials flow) and orchestrates remote actions on managed devices: collecting files (`GetFile`) and executing PowerShell scripts (`RunScript`).

## Build & Run

```bash
# Requires Rust 1.85+ (edition 2024). Stable channel pinned in rust-toolchain.toml.
cargo build
cargo run -- --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> -g --file <PATH>

# Run all tests (unit + integration)
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
  client.rs           # MdeClient — authenticated HTTP wrapper with 401 retry
  error.rs            # MdeError — typed error hierarchy (thiserror)
  live_response.rs    # Live Response models + 4-step orchestration
tests/
  live_response_flow.rs  # Integration tests using wiremock
```

## Architecture

The Live Response flow is a 4-step async pipeline:
1. **POST** `/api/machines/{id}/runliveresponse` — start action
2. **Poll GET** `/api/machineactions/{id}` — wait for terminal status
3. **GET** download link — fetch Azure SAS URL
4. **GET** SAS URL — download raw bytes (no bearer auth)

Key design decisions:
- `MdeClient.auth` uses `tokio::sync::Mutex` so `&self` methods can lazily refresh the token
- `base_url` is configurable for sovereign clouds and test overrides
- Token endpoint URL is configurable via `TokenProvider::with_token_url()`
- `run_live_response()` is a free function borrowing `&MdeClient`, not a method
- `ActionStatus::Unknown` with `#[serde(other)]` for forward-compatible API parsing

## Conventions

- **Error type**: `MdeError` (typed enum via thiserror) with variants: `Auth`, `Api`, `Timeout`, `ActionFailed`, `Parse`, `Network`
- **Serde**: PascalCase field renaming for MDE API contract fidelity (`#[serde(rename = "Commands")]`)
- **Comments**: Explain "why," not "what" — per AGENTS.md
- **Docs**: `#![warn(missing_docs)]` enforced on all public items
- **Testing**: Every public function has tests; tests encode semantics, not implementation
- **No panics** in production paths; early returns with `?`
- **Async/await** everywhere via Tokio; no blocking calls

## Testing

- **Unit tests** are embedded in each module (`auth.rs`, `error.rs`, `live_response.rs`)
- **Integration tests** in `tests/` use `wiremock` to mock both MDE API and SAS download endpoints
- Test helpers: `TokenProvider::with_token()` bypasses Azure AD, `MdeClient::with_base_url()` redirects to mock server

## Dependencies

| Crate | Purpose |
|-------|---------|
| `clap` (derive, env) | CLI argument parsing with env var support |
| `reqwest` (json, form) | Async HTTP client |
| `serde` / `serde_json` | JSON serialization |
| `serde_urlencoded` | Form-encoded serialization for token requests |
| `thiserror` | Typed error derivation |
| `tokio` (full) | Async runtime |
| `bytes` | Byte buffer handling |
| `wiremock` (dev) | HTTP mocking for tests |
