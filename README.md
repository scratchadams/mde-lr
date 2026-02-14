# mde-lr

An async Rust CLI client for [Microsoft Defender for Endpoint (MDE)](https://learn.microsoft.com/en-us/defender-endpoint/) Live Response. Authenticates via Azure AD OAuth2 client credentials and orchestrates remote actions on managed devices — collecting files, executing scripts, and downloading results.

## What It Does

MDE Live Response lets security teams interact with devices remotely through the MDE API. This tool wraps the full 4-step async flow into a single CLI invocation:

1. **Start** — `POST /api/machines/{id}/runliveresponse` creates the action (returns `Pending`).
2. **Poll** — `GET /api/machineactions/{id}` waits until the action reaches a terminal state (`Succeeded`, `Failed`, or `Cancelled`).
3. **Link** — `GET .../GetLiveResponseResultDownloadLink(index=N)` retrieves a time-limited Azure Blob Storage SAS URL.
4. **Download** — `GET {sas_url}` fetches the raw result bytes (no bearer auth; SAS token is in the query string).

The CLI handles token acquisition, token refresh, bounded polling with timeout, one-shot 401 retry, and per-command result download automatically.

## Prerequisites

- **Rust nightly toolchain** — the project uses `edition = "2024"`, which requires nightly. The channel is pinned in `rust-toolchain.toml`, so `rustup` will select it automatically.
- **Azure AD app registration** with the following:
  - `WindowsDefenderATP` API permissions for Live Response (application-level, admin-consented).
  - A client secret (or access to one via environment variable).
- **MDE device ID** for the target machine. Find this in the Microsoft Defender portal or via the MDE machines API.

## Installation

```bash
git clone <repository-url>
cd mde-lr
cargo build --release
```

The binary is at `target/release/mde-lr`.

## Usage

### Collect a File from a Remote Device

```bash
mde-lr \
  --device-id <DEVICE_ID> \
  --tenant-id <AZURE_TENANT_ID> \
  --client-id <AZURE_CLIENT_ID> \
  --secret <CLIENT_SECRET> \
  -g --file "C:\Windows\TEMP\evidence.zip"
```

On success, the CLI prints the byte count of each downloaded result. On failure, it prints the error to stderr and exits with a non-zero code.

### Authentication via Environment Variable (Recommended)

To avoid exposing the client secret in process listings and shell history, set it as an environment variable:

```bash
export MDE_CLIENT_SECRET="your-client-secret"

mde-lr \
  --device-id <DEVICE_ID> \
  --tenant-id <AZURE_TENANT_ID> \
  --client-id <AZURE_CLIENT_ID> \
  -g --file "C:\temp\log.zip"
```

The `--secret` flag reads from `MDE_CLIENT_SECRET` automatically when not provided on the command line.

### CLI Reference

| Flag | Required | Description |
|---|---|---|
| `--device-id` | Yes | MDE device ID to target |
| `--tenant-id` | Yes | Azure AD tenant ID for OAuth2 |
| `--client-id` | Yes | Azure AD application (client) ID |
| `--secret` | Yes | Client secret (or set `MDE_CLIENT_SECRET` env var) |
| `-g` | One of `-g`, `-p`, `-d` | GetFile action — collect a file from the remote device |
| `-p` | One of `-g`, `-p`, `-d` | Put action (not yet implemented) |
| `-d` | One of `-g`, `-p`, `-d` | Download action (not yet implemented) |
| `--file` | When using `-g` | Remote file path to collect |

Exactly one action flag (`-g`, `-p`, or `-d`) must be provided per invocation. The CLI enforces this at parse time.

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Runtime error (auth failure, API error, polling timeout, etc.) |
| `2` | Argument validation error (missing required flags, conflicting actions) |

## Project Structure

```
src/
  lib.rs              # Crate root — re-exports auth, client, live_response
  main.rs             # CLI entry point (clap-derived argument parsing)
  auth.rs             # OAuth2 TokenProvider — token acquisition, caching, expiry
  client.rs           # MdeClient — authenticated HTTP wrapper with 401 retry
  live_response.rs    # Live Response models + 4-step orchestration
tests/
  live_response_flow.rs  # Integration tests using wiremock mock server
```

## Architecture

The crate is organized into three modules with clear responsibilities:

**`auth`** — Manages the OAuth2 client credentials flow against Azure AD's `/oauth2/v2.0/token` endpoint. Caches the token and tracks its expiry with a 60-second safety buffer. Callers never need to explicitly "log in" — the first API request triggers token acquisition automatically.

**`client`** — Wraps `reqwest::Client` with bearer-token authentication and a one-shot 401 retry mechanism. If the MDE API returns `401 Unauthorized`, the client invalidates the cached token, acquires a fresh one from Azure AD, and retries exactly once. A second 401 is treated as a hard failure. The token is stored behind a `tokio::sync::Mutex` so `&self` methods can refresh it without requiring `&mut self`.

**`live_response`** — Contains the request/response types for the MDE Live Response API and the `run_live_response()` orchestration function. Polling is bounded by a configurable timeout (default 10 minutes) and interval (default 5 seconds). The `ActionStatus` enum uses `#[serde(other)]` for forward compatibility with new API status values.

```
main.rs ──> MdeClient ──> TokenProvider
   │            │
   │            └──> reqwest::Client
   │
   └──> run_live_response() ──> MdeClient (via &self)
```

`run_live_response` is a free function that borrows `&MdeClient`, not a method on it. This keeps the HTTP transport layer separate from orchestration logic.

For a detailed architecture document covering state diagrams, failure semantics, sequence diagrams, design decisions, and configuration defaults, see [architecture.md](architecture.md).

## Library Usage

`mde-lr` is also a library crate. You can use it programmatically:

```rust
use mde_lr::auth::TokenProvider;
use mde_lr::client::MdeClient;
use mde_lr::live_response::{
    Command, CommandType, LiveResponseRequest, Param,
    PollConfig, ScriptResult, run_live_response,
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Authenticate
    let tp = TokenProvider::new(
        "your-tenant-id",
        "your-client-id",
        "your-client-secret",
        "https://api.securitycenter.microsoft.com/.default",
    );
    let client = MdeClient::new(tp).await;

    // Build a GetFile request
    let request = LiveResponseRequest {
        comment: "Collect forensic artifact".to_string(),
        commands: vec![Command {
            command_type: CommandType::GetFile,
            params: vec![Param {
                key: "Path".to_string(),
                value: "C:\\Windows\\TEMP\\evidence.zip".to_string(),
            }],
        }],
    };

    // Run with default polling (5s interval, 10min timeout)
    let results = run_live_response(&client, "device-id", &request, None).await?;
    println!("Downloaded {} bytes", results[0].len());

    // Or customize polling behavior
    let poll_config = PollConfig::new(
        Duration::from_secs(10),  // poll every 10s
        Duration::from_secs(300), // timeout after 5min
    );
    let results = run_live_response(
        &client, "device-id", &request, Some(&poll_config),
    ).await?;

    // For RunScript commands, parse the result as JSON
    let script_result: ScriptResult = serde_json::from_slice(&results[0])?;
    println!("Exit code: {}", script_result.exit_code);
    println!("Output: {}", script_result.script_output);

    Ok(())
}
```

## Configuration Defaults

| Setting | Value | Rationale |
|---|---|---|
| Token connect timeout | 10s | TCP + TLS handshake to Azure AD |
| Token request timeout | 30s | Full round-trip for token acquisition |
| API connect timeout | 10s | TCP + TLS handshake to MDE API |
| API request timeout | 5 min | Accommodates large file downloads via SAS URLs |
| Token expiry buffer | 60s | Prevents edge-of-expiry request failures |
| Poll interval | 5s | Balances responsiveness against API rate limits |
| Poll timeout | 10 min | Covers long-running scripts and large file collections |

## Failure Handling

| Scenario | What happens |
|---|---|
| Token request fails | Error includes HTTP status and raw Azure AD error body (AADSTS codes) |
| API returns 401 | Token is invalidated, refreshed, and the request is retried once |
| API returns 401 a second time | Hard error — no further retries |
| API returns other 4xx/5xx | Immediate error (no retry) |
| Action status is `Failed` or `Cancelled` | Error includes the status and action ID |
| Polling exceeds timeout | Error includes the timeout duration and action ID |
| Unrecognized action status | Treated as non-terminal; polling continues |

## Development

### Build and Test

```bash
# Build
cargo build

# Run all tests (19 unit + 4 integration)
cargo test

# Run a specific test
cargo test full_getfile_flow

# Lint
cargo clippy --all-targets --all-features -- -D warnings

# Format
cargo fmt
```

### How Tests Work

Integration tests use [wiremock](https://crates.io/crates/wiremock) to mock both the MDE API and Azure Blob Storage in a single in-process HTTP server. This works because:

1. `MdeClient::with_base_url()` redirects API calls to the mock server.
2. The mock for `GetLiveResponseResultDownloadLink` returns a SAS URL that also points at the mock server.
3. `MdeClient::download()` uses the same `reqwest::Client`, so SAS downloads also hit the mock.

All four steps of the live response flow execute without any real network calls. `TokenProvider::with_token()` bypasses Azure AD entirely by pre-setting a token.

### Dependencies

| Crate | Purpose |
|---|---|
| `clap` (derive, env) | CLI argument parsing with env var support |
| `reqwest` (json, form) | Async HTTP client for API and token requests |
| `serde` / `serde_json` | JSON serialization with PascalCase field renaming |
| `serde_urlencoded` | Form-encoded serialization for OAuth2 token requests |
| `tokio` (full) | Async runtime |
| `bytes` | Zero-copy byte buffer for download results |
| `wiremock` (dev) | HTTP mock server for integration tests |

## Roadmap

The project follows a phased plan. Phase 1 (production correctness) is complete:

- [x] Token expiry tracking with safety buffer
- [x] Bounded polling with configurable timeout
- [x] Typed action status enum with forward compatibility
- [x] One-shot 401 retry on stale tokens
- [x] Explicit HTTP timeouts (separate profiles for token vs API)
- [x] CLI exit codes and argument validation
- [x] Client secret via environment variable

Planned next:

- [ ] Typed error enum replacing `Box<dyn Error>` — preserves API error bodies
- [ ] Configurable cloud endpoints (sovereign/government clouds)
- [ ] Public API surface audit and `#![warn(missing_docs)]`
- [ ] CI workflow (fmt, clippy, test, doc)
- [ ] Integration tests for 401 retry and polling timeout paths
- [ ] `-p` (put) and `-d` (download) action implementations

See [architecture.md](architecture.md) for detailed design documentation including state diagrams, sequence diagrams, and decision records.

## License

TBD
