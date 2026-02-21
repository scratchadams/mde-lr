# mde-lr

An async Rust CLI client and library for [Microsoft Defender for Endpoint (MDE)](https://learn.microsoft.com/en-us/defender-endpoint/). Authenticates via Azure AD OAuth2 client credentials and orchestrates remote actions on managed devices — collecting files, executing scripts, downloading results, isolating machines, running AV scans, and more.

## What It Does

`mde-lr` covers five MDE API families:

**Live Response** — Remote file collection, script execution, and file upload via the 4-step async flow (POST → poll → download link → SAS download).

**Machines** — Device lookup, listing (with OData filtering), and metadata updates (tags, device value).

**Machine Actions** — Incident response operations: isolate/unisolate devices, run AV scans, collect investigation packages, stop and quarantine files, and restrict/unrestrict code execution.

**Library** — Live Response library file management: list, upload (multipart), and delete scripts and tools.

**Alerts** — Security alert triage: list (with OData filtering), get details, update individual alerts, and batch-update multiple alerts.

The CLI handles token acquisition, token refresh, bounded polling with timeout, one-shot 401 retry, 429 throttle retry, and per-command result download automatically.

## Prerequisites

- **Rust 1.88.0** — this repository pins a specific toolchain in `rust-toolchain.toml` and declares `rust-version = "1.88"` in `Cargo.toml`. Using the pinned version avoids proc-macro ABI drift in editor tooling.
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
  -g --file "C:\Windows\TEMP\evidence.zip" \
  --out ./evidence.zip
```

The `--out` flag specifies where to save the downloaded file. Without it, the CLI reports the byte count but discards the data.

### Execute a Script on a Remote Device

```bash
mde-lr \
  --device-id <DEVICE_ID> \
  --tenant-id <AZURE_TENANT_ID> \
  --client-id <AZURE_CLIENT_ID> \
  --secret <CLIENT_SECRET> \
  -r --script "Invoke-VerboseTraceroute.ps1" --args "8.8.8.8,1.1.1.1"
```

The script must already exist in the MDE Live Response library. On success, the CLI displays the script name, exit code, stdout, and stderr.

### Upload a File to a Remote Device

```bash
mde-lr \
  --device-id <DEVICE_ID> \
  --tenant-id <AZURE_TENANT_ID> \
  --client-id <AZURE_CLIENT_ID> \
  --secret <CLIENT_SECRET> \
  -p --file "C:\tools\agent.exe"
```

On success, the CLI prints the byte count of each result. On failure, it prints the error to stderr and exits with a non-zero code.

### Machine Actions

```bash
# Isolate a device from the network
mde-lr --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> \
  --isolate --comment "Contain compromised host" --isolation-type Full

# Release a device from isolation
mde-lr --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> \
  --unisolate --comment "Device cleared"

# Run an antivirus scan
mde-lr --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> \
  --scan --comment "Routine check" --scan-type Quick

# Collect an investigation package
mde-lr --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> \
  --collect-investigation --comment "Gather forensic artifacts"

# Stop and quarantine a file by SHA-1
mde-lr --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> \
  --stop-quarantine --comment "Quarantine malware" --sha1 <SHA1_HASH>

# Restrict code execution on a device
mde-lr --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> \
  --restrict-execution --comment "Lock down compromised device"

# Unrestrict code execution
mde-lr --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> \
  --unrestrict-execution --comment "Device cleaned, lift restriction"
```

Machine actions are fire-and-forget by default — the CLI prints the action ID and initial status. Use the action ID in the MDE portal to track progress.

### Library Management

```bash
# List all library files
mde-lr --tenant-id <TID> --client-id <CID> --secret <S> \
  --list-library

# Upload a script to the library
mde-lr --tenant-id <TID> --client-id <CID> --secret <S> \
  --upload-library --file ./collector.ps1 --description "Forensic collector"

# Delete a library file
mde-lr --tenant-id <TID> --client-id <CID> --secret <S> \
  --delete-library --file "collector.ps1"
```

### Alert Workflows

```bash
# List all alerts
mde-lr --tenant-id <TID> --client-id <CID> --secret <S> \
  --list-alerts

# List alerts with OData filter
mde-lr --tenant-id <TID> --client-id <CID> --secret <S> \
  --list-alerts --filter "severity eq 'High'"

# Get a specific alert
mde-lr --tenant-id <TID> --client-id <CID> --secret <S> \
  --get-alert --alert-id <ALERT_ID>

# Update an alert (status, classification, assignment, comment)
mde-lr --tenant-id <TID> --client-id <CID> --secret <S> \
  --update-alert --alert-id <ALERT_ID> \
  --status Resolved --classification FalsePositive \
  --determination NotMalicious --assigned-to "analyst@contoso.com" \
  --comment "Confirmed false positive"

# Batch update multiple alerts
mde-lr --tenant-id <TID> --client-id <CID> --secret <S> \
  --batch-update-alerts --alert-ids "alert-1,alert-2,alert-3" \
  --status Resolved --classification FalsePositive \
  --comment "Batch close — false positives"
```

### Machine Queries

```bash
# Get details for a specific machine
mde-lr --device-id <ID> --tenant-id <TID> --client-id <CID> --secret <S> \
  --get-machine

# List machines (all)
mde-lr --tenant-id <TID> --client-id <CID> --secret <S> \
  --list-machines

# List machines with OData filter
mde-lr --tenant-id <TID> --client-id <CID> --secret <S> \
  --list-machines --filter "healthStatus eq 'Active'"
```

### Authentication via Environment Variable (Recommended)

To avoid exposing the client secret in process listings and shell history, set it as an environment variable:

```bash
export MDE_CLIENT_SECRET="your-client-secret"

# GetFile
mde-lr --device-id <ID> --tenant-id <TID> --client-id <CID> \
  -g --file "C:\temp\log.zip"

# RunScript
mde-lr --device-id <ID> --tenant-id <TID> --client-id <CID> \
  -r --script "whoami.ps1"

# PutFile
mde-lr --device-id <ID> --tenant-id <TID> --client-id <CID> \
  -p --file "C:\tools\utility.exe"
```

The `--secret` flag reads from `MDE_CLIENT_SECRET` automatically when not provided on the command line.

### CLI Reference

| Flag | Required | Description |
|---|---|---|
| `--device-id` | Some actions | MDE device ID to target (not required for library, alert, `--list-machines`, or `-t` actions) |
| `--tenant-id` | Yes | Azure AD tenant ID for OAuth2 |
| `--client-id` | Yes | Azure AD application (client) ID |
| `--secret` | Yes | Client secret (or set `MDE_CLIENT_SECRET` env var) |
| `-g` | One action | GetFile — collect a file from the remote device |
| `-r` | One action | RunScript — execute a PowerShell script on the device |
| `-p` | One action | PutFile — upload a file from the MDE library to the device |
| `-t` | One action | Token inspection — acquire and print OAuth2 token |
| `--isolate` | One action | Isolate a device from the network |
| `--unisolate` | One action | Release a device from network isolation |
| `--scan` | One action | Run a Microsoft Defender Antivirus scan |
| `--collect-investigation` | One action | Collect a forensic investigation package |
| `--stop-quarantine` | One action | Stop and quarantine a file by SHA-1 hash |
| `--restrict-execution` | One action | Restrict application execution on a device |
| `--unrestrict-execution` | One action | Remove app execution restrictions |
| `--get-machine` | One action | Get details for a specific machine |
| `--list-machines` | One action | List machines (with optional `--filter`) |
| `--list-library` | One action | List all Live Response library files |
| `--upload-library` | One action | Upload a file to the Live Response library |
| `--delete-library` | One action | Delete a file from the Live Response library |
| `--list-alerts` | One action | List security alerts (with optional `--filter`) |
| `--get-alert` | One action | Get a specific alert by ID |
| `--update-alert` | One action | Update an alert (status, classification, assignment, comment) |
| `--batch-update-alerts` | One action | Batch-update multiple alerts at once |
| `--file` | `-g`, `-p`, library | Remote file path to collect/upload, or library filename to delete |
| `--script` | `-r` | Script name (must exist in MDE library) |
| `--args` | No | Arguments for the script (supports hyphen-prefixed values) |
| `--out` | No | Output file path for saving downloaded results to disk |
| `--comment` | Machine actions | Audit comment (required for all machine action endpoints) |
| `--isolation-type` | `--isolate` | Isolation type: `Full` (default), `Selective`, or `UnManagedDevice` |
| `--scan-type` | `--scan` | Scan type: `Quick` (default) or `Full` |
| `--sha1` | `--stop-quarantine` | SHA-1 hash of the file to quarantine |
| `--filter` | `--list-machines`, `--list-alerts` | OData `$filter` expression for filtering results |
| `--description` | `--upload-library` | Description for the uploaded library file |
| `--alert-id` | `--get-alert`, `--update-alert` | Alert ID to retrieve or update |
| `--alert-ids` | `--batch-update-alerts` | Comma-separated alert IDs for batch update |
| `--status` | Alert updates | Alert status: `New`, `InProgress`, or `Resolved` |
| `--classification` | Alert updates | Alert classification (e.g., `FalsePositive`, `TruePositive`) |
| `--determination` | Alert updates | Alert determination (e.g., `NotMalicious`, `Malware`) |
| `--assigned-to` | Alert updates | Email of the analyst to assign the alert to |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Runtime error (auth failure, API error, polling timeout, etc.) |
| `2` | Argument validation error (missing required flags, conflicting actions) |

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
  machines.rs         # Machines family — list, get, update machine endpoints
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

The crate is organized into nine modules with clear responsibilities:

**`auth`** — Manages the OAuth2 client credentials flow against Azure AD's `/oauth2/v2.0/token` endpoint. Caches the token and tracks its expiry with a 60-second safety buffer. Callers never need to explicitly "log in" — the first API request triggers token acquisition automatically.

**`client`** — Wraps `reqwest::Client` with bearer-token authentication, a one-shot 401 retry mechanism, and configurable 429 throttle retry with `Retry-After` header support. The token is stored behind a `tokio::sync::Mutex` so `&self` methods can refresh it without requiring `&mut self`. Supports GET, POST, PUT, PATCH, DELETE, and multipart upload.

**`error`** — Typed error hierarchy (`MdeError`) with variants for each failure boundary: `Auth`, `Api` (preserves response body), `Timeout`, `ActionFailed`, `Throttled`, `Parse`, and `Network`.

**`action`** — Shared polling abstraction used by all action-based endpoint families. Contains `ActionStatus`, `MachineAction`, `PollConfig`, and the `poll_action()` function. Extracted from `live_response` for reuse across machine actions.

**`live_response`** — Request/response types for the MDE Live Response API and the `run_live_response()` 4-step orchestration function (POST → poll → download link → SAS download).

**`machines`** — Machine lookup, listing with OData filtering, and metadata updates. Provides `Machine` struct, `ODataList<T>` generic collection wrapper, and `UpdateMachineRequest`.

**`machine_actions`** — Seven incident response endpoints: isolate, unisolate, AV scan, collect investigation package, stop and quarantine file, restrict/unrestrict code execution. All follow a shared POST → optional-poll pattern via `post_and_poll()`.

**`library`** — Live Response library file management. List files (OData collection), upload via multipart/form-data (no auto-retry since form is consumed on send), and delete (204 No Content).

**`alerts`** — Security alert triage. List with OData filtering, get by ID, update individual alerts (PATCH), and batch-update multiple alerts. Evidence is stored as `serde_json::Value` (polymorphic, deferred typing).

```
main.rs ──> MdeClient ──────────> TokenProvider
   │            │
   │            └──> reqwest::Client
   │
   ├──> run_live_response()     ──> MdeClient + poll_action()
   ├──> machines::*()           ──> MdeClient
   ├──> machine_actions::*()    ──> MdeClient + poll_action()
   ├──> library::*()            ──> MdeClient
   └──> alerts::*()             ──> MdeClient
```

All endpoint functions are free functions that borrow `&MdeClient`, not methods on it. This keeps the HTTP transport layer separate from endpoint-specific logic.

For a detailed architecture document covering state diagrams, failure semantics, sequence diagrams, design decisions, and configuration defaults, see [architecture.md](architecture.md).

## Library Usage

`mde-lr` is also a library crate. You can use it programmatically:

```rust
use mde_lr::auth::TokenProvider;
use mde_lr::client::MdeClient;
use mde_lr::error::MdeError;
use mde_lr::live_response::{
    Command, CommandType, LiveResponseRequest, Param,
    PollConfig, ScriptResult, run_live_response,
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), MdeError> {
    // Authenticate (commercial cloud — pass None for default base URL)
    let tp = TokenProvider::new(
        "your-tenant-id",
        "your-client-id",
        "your-client-secret",
        "https://api.securitycenter.microsoft.com/.default",
    );
    let client = MdeClient::new(tp, None).await;

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

    // PutFile example — upload a file from the MDE library to the device
    let put_request = LiveResponseRequest {
        comment: "Deploy utility".to_string(),
        commands: vec![Command {
            command_type: CommandType::PutFile,
            params: vec![Param {
                key: "Path".to_string(),
                value: "C:\\tools\\agent.exe".to_string(),
            }],
        }],
    };
    let _results = run_live_response(&client, "device-id", &put_request, None).await?;

    Ok(())
}
```

### Machine Actions

```rust
use mde_lr::action::PollConfig;
use mde_lr::machine_actions::*;
use mde_lr::machines;

// Isolate a device (fire-and-forget)
let action = isolate_machine(
    &client, "device-id",
    &IsolateRequest {
        comment: "Contain compromised host".to_string(),
        isolation_type: "Full".to_string(),
    },
    None, // No polling — returns immediately with Pending action
).await?;
println!("Action {} status: {:?}", action.id, action.status);

// Isolate and wait for completion
let action = isolate_machine(
    &client, "device-id",
    &IsolateRequest {
        comment: "Contain compromised host".to_string(),
        isolation_type: "Full".to_string(),
    },
    Some(&PollConfig::default()), // Poll until Succeeded/Failed/Cancelled
).await?;

// List machines with OData filter
let machines = machines::list_machines(
    &client, Some("healthStatus eq 'Active'"),
).await?;
for machine in &machines.value {
    println!("{}: {}", machine.id, machine.computer_dns_name);
}

// Get a specific machine
let machine = machines::get_machine(&client, "device-id").await?;
println!("OS: {}, Health: {}", machine.os_platform, machine.health_status);
```

### Library and Alert Management

```rust
use mde_lr::library;
use mde_lr::alerts::{self, UpdateAlertRequest, BatchUpdateAlertsRequest};

// List library files
let files = library::list_library_files(&client).await?;
for f in &files {
    println!("{}: {}", f.file_name, f.sha256.as_deref().unwrap_or("n/a"));
}

// Upload a script to the library
let uploaded = library::upload_library_file(
    &client,
    "collector.ps1",
    std::fs::read("collector.ps1")?,
    Some("Forensic collector script"),
    false, // override_if_exists
).await?;

// Delete a library file
library::delete_library_file(&client, "old-script.ps1").await?;

// List alerts with OData filter
let alerts = alerts::list_alerts(&client, Some("severity eq 'High'")).await?;

// Get a specific alert
let alert = alerts::get_alert(&client, "alert-123").await?;
println!("Alert: {} — {}", alert.id, alert.title.as_deref().unwrap_or(""));

// Update an alert
let update = UpdateAlertRequest {
    status: Some("Resolved".to_string()),
    classification: Some("FalsePositive".to_string()),
    determination: Some("NotMalicious".to_string()),
    assigned_to: Some("analyst@contoso.com".to_string()),
    comment: Some("Confirmed false positive".to_string()),
};
let updated = alerts::update_alert(&client, "alert-123", &update).await?;

// Batch update alerts
let batch = BatchUpdateAlertsRequest {
    alert_ids: vec!["alert-1".into(), "alert-2".into()],
    status: Some("Resolved".to_string()),
    classification: Some("FalsePositive".to_string()),
    determination: Some("NotMalicious".to_string()),
    assigned_to: None,
    comment: Some("Batch close".to_string()),
};
alerts::batch_update_alerts(&client, &batch).await?;
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
| API returns 429 (throttled) | Reads `Retry-After` header, retries up to 3 times (configurable) |
| API returns 429 beyond retry budget | `MdeError::Throttled` with the requested delay |
| API returns other 4xx/5xx | Immediate error (no retry) |
| Action status is `Failed` or `Cancelled` | Error includes the status and action ID |
| Polling exceeds timeout | Error includes the timeout duration and action ID |
| Unrecognized action status | Treated as non-terminal; polling continues |

## Development

### Build and Test

```bash
# Build
cargo build

# Run all tests (111 unit + 36 integration = 147 total)
cargo test

# Run a specific test
cargo test full_getfile_flow

# Lint
cargo clippy --all-targets --all-features -- -D warnings

# Format
cargo fmt
```

### How Tests Work

Integration tests use [wiremock](https://crates.io/crates/wiremock) to mock the MDE API in a single in-process HTTP server. `MdeClient::with_base_url()` redirects all API calls to the mock server, and `TokenProvider::with_token()` bypasses Azure AD entirely. Six test suites cover:

- **`live_response_flow.rs`** (7 tests) — Full 4-step flow, failure paths, polling progression
- **`machines_flow.rs`** (7 tests) — List/get/update with OData filter, error handling
- **`machine_actions_flow.rs`** (7 tests) — Isolate, scan, quarantine, restrict, API errors
- **`library_flow.rs`** (5 tests) — List, upload (multipart), delete (204), delete 404, empty list
- **`alerts_flow.rs`** (7 tests) — List with filter, get, update, batch update, error paths
- **`manifest_validation.rs`** (3 tests) — TOML schema, implemented endpoints, HTTP verb validation

### Dependencies

| Crate | Purpose |
|---|---|
| `clap` (derive, env) | CLI argument parsing with env var support |
| `reqwest` (json, form, multipart) | Async HTTP client for API, token, and file upload requests |
| `serde` / `serde_json` | JSON serialization with PascalCase field renaming |
| `serde_urlencoded` | Form-encoded serialization for OAuth2 token requests |
| `thiserror` | Typed error derivation with source chaining |
| `tokio` (full) | Async runtime |
| `bytes` | Zero-copy byte buffer for download results |
| `toml` (dev) | TOML deserialization for manifest validation tests |
| `wiremock` (dev) | HTTP mock server for integration tests |

## Roadmap

The project follows a phased plan. Phases 1-4 are complete:

**Phase 1** (production correctness):
- [x] Token expiry tracking with safety buffer
- [x] Bounded polling with configurable timeout
- [x] Typed action status enum with forward compatibility
- [x] One-shot 401 retry on stale tokens
- [x] Explicit HTTP timeouts (separate profiles for token vs API)
- [x] CLI exit codes and argument validation
- [x] Client secret via environment variable

**Phase 2** (library hardening):
- [x] Typed `MdeError` enum with thiserror (preserves API error bodies)
- [x] Configurable cloud endpoints (sovereign/government clouds)
- [x] Public API surface audit and `#![warn(missing_docs)]`
- [x] Stable toolchain migration with explicit pinning (`1.88.0`)
- [x] Crate metadata (description, keywords, license)

**Phase 3** (quality gates):
- [x] CI workflow (fmt, clippy, test, doc)
- [x] Integration tests for 401 retry and polling timeout paths
- [x] Expanded test coverage

**Phase 4** (CLI feature expansion):
- [x] RunScript CLI action (`-r --script --args`)
- [x] PutFile CLI action (`-p --file`)
- [x] Token inspection flag (`-t`)
- [x] `--out` flag for saving downloaded results to disk
- [x] Structured script result output (exit code, stdout, stderr)
- [x] Documentation updates across all project files

**Milestone 0** (foundation for expansion):
- [x] PATCH, DELETE, multipart upload client methods
- [x] 204 No Content handling for delete endpoints
- [x] 429 throttle retry with configurable `RetryPolicy` and `Retry-After` header
- [x] `MdeError::Throttled` error variant
- [x] Endpoint manifest (`manifest/endpoints.toml`) with CI schema/structural validation
- [x] Codegen boundary definition in architecture docs

**Milestone 1** (core incident response):
- [x] Extracted shared action-polling abstraction (`action.rs`)
- [x] Machines family — list (OData filter), get, update (3 endpoints)
- [x] Machine Actions family — isolate, unisolate, AV scan, collect investigation, stop quarantine, restrict/unrestrict (7 endpoints)
- [x] CLI integration for all new endpoints (9 new flags)
- [x] 24 new integration tests + 24 new unit tests
- [x] Manifest updated: 14/32 endpoints implemented
- [x] Test coverage: 113 total (89 unit + 24 integration)

**Milestone 2** (library + alert workflows):
- [x] Library family — list, upload (multipart), delete (3 endpoints)
- [x] Alerts family — list (OData filter), get, update, batch-update (4 endpoints)
- [x] `patch_no_content()` client method for PATCH with empty response body
- [x] CLI integration: 8 new action flags + 7 supporting params
- [x] 12 new integration tests + 22 new unit tests
- [x] Manifest updated: 21/32 endpoints implemented (66%)
- [x] Test coverage: 147 total (111 unit + 36 integration)

Planned next (see [roadmap.md](roadmap.md)):

- [ ] Milestone 3: Hunting + indicators
- [ ] Structured logging/tracing (`tracing` crate)
- [ ] Streaming write-to-disk for large file downloads (currently buffered in memory)
- [ ] Workspace split (separate library/CLI crates) when a second consumer emerges

See [architecture.md](architecture.md) for detailed design documentation including state diagrams, sequence diagrams, and decision records.

## License

MIT
