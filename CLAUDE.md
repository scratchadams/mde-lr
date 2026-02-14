# CLAUDE.md

## Project Overview

**mde-lr** is an async Rust CLI client for Microsoft Defender for Endpoint (MDE) Live Response. It authenticates via Azure AD OAuth2 (client credentials flow) and orchestrates remote actions on managed devices: collecting files (`GetFile`) and executing PowerShell scripts (`RunScript`).

## Build & Run

```bash
# Requires nightly Rust (set in rust-toolchain.toml, edition 2024)
cargo build
cargo run -- --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> -g --file <PATH>

# Run all tests (unit + integration)
cargo test

# Run a specific test
cargo test full_getfile_flow
```

## Project Structure

```
src/
  lib.rs              # Module exports (auth, client, live_response)
  main.rs             # CLI entry point (clap-derived args)
  auth.rs             # OAuth2 TokenProvider — token request, cache, refresh
  client.rs           # MdeClient — authenticated HTTP wrapper over reqwest
  live_response.rs    # Live Response API orchestration (4-step flow)
tests/
  live_response_flow.rs  # Integration tests using wiremock
```

## Architecture

The Live Response flow is a 4-step async pipeline:
1. **POST** `/api/machines/{id}/runliveresponse` — start action
2. **Poll GET** `/api/machineactions/{id}` — wait for terminal status (5s intervals)
3. **GET** download link — fetch Azure SAS URL
4. **GET** SAS URL — download raw bytes (no bearer auth)

Key design decisions:
- `MdeClient.auth` uses `Mutex` so `&self` methods can lazily refresh the token
- `base_url` is `String` (not `&'static str`) to support test overrides
- Generic `send_json<T, B>()` enables flexible request/response types
- `TokenProvider::with_token()` and `MdeClient::with_base_url()` are test constructors

## Conventions

- **Error type**: `Result<T, Box<dyn Error + Send + Sync>>` throughout
- **Serde**: PascalCase field renaming for MDE API contract fidelity (`#[serde(rename = "Commands")]`)
- **Comments**: Explain "why," not "what" — per AGENTS.md
- **Testing**: Every public function has tests; tests encode semantics, not implementation
- **No panics** in production paths; early returns with `?`
- **Async/await** everywhere via Tokio; no blocking calls

## Testing

- **Unit tests** are embedded in each module (`auth.rs`, `live_response.rs`)
- **Integration tests** in `tests/` use `wiremock` to mock both MDE API and SAS download endpoints
- Test helpers: `TokenProvider::with_token()` bypasses Azure AD, `MdeClient::with_base_url()` redirects to mock server

## Dependencies

| Crate | Purpose |
|-------|---------|
| `clap` (derive) | CLI argument parsing |
| `reqwest` (json, form) | Async HTTP client |
| `serde` / `serde_json` | JSON serialization |
| `tokio` (full) | Async runtime |
| `bytes` | Byte buffer handling |
| `wiremock` (dev) | HTTP mocking for tests |
