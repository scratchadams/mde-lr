# mde-lr Architecture

Status: Draft
Owner: mde-lr maintainers
Last updated: 2026-02-20

## 1. Purpose and Scope

This document explains how `mde-lr` is built today: module boundaries,
runtime flow, failure semantics, and key design choices.

`mde-lr` is an async Rust CLI and library for Microsoft Defender for Endpoint
(MDE). The implemented surface covers five API families: Live Response
(GetFile, RunScript, PutFile), Machines (list, get, update), Machine
Actions (isolate, unisolate, AV scan, collect investigation package, stop and
quarantine file, restrict/unrestrict code execution), Library (list, upload,
delete), and Alerts (list, get, update, batch-update). 21 of 32 manifest
endpoints are implemented.

Observability is treated as a first-class engineering value for the next
expansion phase: failures should be diagnosable with structured context from
both runtime behavior and test artifacts.

**Toolchain requirement:** The project uses `edition = "2024"` (set in
`Cargo.toml`) and is pinned to **Rust 1.88.0** via `rust-toolchain.toml` with
`rust-version = "1.88"` declared in `Cargo.toml`. A fixed version avoids
proc-macro ABI drift between Cargo builds and editor tooling (e.g.
`Serialize`/`Deserialize` derives in rust-analyzer).

## 2. System Context

```text
+---------------------------+          +----------------------------------+
| Operator / Automation     |  CLI     | mde-lr process                   |
| (terminal, CI, scripts)   +--------->| - clap arg parsing               |
+---------------------------+          | - auth token cache/refresh       |
                                       | - MDE API orchestration          |
                                       +----------------+-----------------+
                                                        |
                                   HTTPS (Bearer token) |
                                                        v
                                       +-------------------------------+
                                       | MDE API                       |
                                       | api.security.microsoft.com    |
                                       +---------------+---------------+
                                                       |
                                 HTTPS (SAS URL, no bearer auth)
                                                       |
                                                       v
                                       +-------------------------------+
                                       | Azure Blob (SAS)              |
                                       | downloaded result payload     |
                                       +-------------------------------+

Separate auth dependency:
  mde-lr -> login.microsoftonline.com (OAuth2 client_credentials)
```

All four external calls (token acquisition, action creation, polling, download)
happen **sequentially** within a single `run_live_response` invocation — there
is no parallelism across steps.

## 3. Design Constraints and Invariants

| Constraint / Invariant | Why it exists | Where enforced |
|---|---|---|
| API calls must carry valid bearer token | MDE API requires OAuth2 app auth | `src/client.rs` (`bearer_token`, `send_json`) |
| Cached token must refresh before hard expiry | Avoid edge-of-expiry failures | `src/auth.rs` (`EXPIRY_BUFFER_SECS=60`, `is_expired`) |
| Token acquisition is lazy | No explicit "login" step required; first request triggers refresh automatically | `src/client.rs` (`bearer_token` checks `token()`, refreshes if `None`) |
| Mutex lock is never held across HTTP round-trips | Prevents serializing all API calls behind a single lock | `src/client.rs` (`bearer_token` and `force_refresh` clone the token string, then release the lock before any HTTP call) |
| Polling must terminate | Prevent infinite hangs | `src/action.rs` (`PollConfig.timeout`, `poll_action`) |
| Unknown action statuses must not crash deserialization | Forward compatibility with API changes | `ActionStatus::Unknown` with `#[serde(other)]` in `src/action.rs` |
| SAS download must not attach bearer auth | SAS URL already carries authorization via query-string token | `MdeClient::download` |
| Token endpoint uses form-encoded bodies, not JSON | Azure AD `/oauth2/v2.0/token` requires `application/x-www-form-urlencoded` | `src/auth.rs` (`reqwest::RequestBuilder::form()` serializes via `serde_urlencoded`) |
| Public API surface returns fallible async results | Explicit failure handling across network boundaries | `Result<T, MdeError>` typed error hierarchy |
| Failure diagnostics must include actionable context | External API failures require fast root-cause isolation | `MdeError` preserves status/body; tests assert failure-path behavior |
| 429 throttle must be retried with backoff | MDE API enforces per-endpoint rate limits (100 calls/min) | `src/client.rs` (`send_json`, `send_no_content`) honor `Retry-After` header up to `RetryPolicy::max_retries` |
| Multipart uploads are not retried | `reqwest::multipart::Form` is consumed on send (not `Clone`) | `src/client.rs` (`upload_multipart`) — callers retry at the application level |

## 4. Module Architecture

### 4.1 Code Layout

| Module | Responsibility | External side effects |
|---|---|---|
| `src/lib.rs` | Crate root — re-exports all public modules | None (module declaration only) |
| `src/main.rs` | CLI parsing and command dispatch for all 21 action flags | stdout/stderr, process exit code |
| `src/auth.rs` | OAuth2 token acquisition + cache lifecycle | HTTPS to Azure AD token endpoint |
| `src/client.rs` | Authenticated HTTP wrapper with 401/429 retry, PATCH/DELETE/multipart | HTTPS to MDE API and SAS URLs |
| `src/error.rs` | Typed error hierarchy (`MdeError`) for all library operations | None (type definitions only) |
| `src/action.rs` | Shared action-polling abstraction (`ActionStatus`, `MachineAction`, `PollConfig`, `poll_action`) | None (reused by `live_response` and `machine_actions`) |
| `src/live_response.rs` | Live Response request/response models + 4-step orchestration | Polling loop + downloads |
| `src/machines.rs` | Machines family — list (OData filter), get, update endpoints | HTTPS to MDE API |
| `src/machine_actions.rs` | Machine Actions family — 7 incident response endpoints with POST → poll pattern | HTTPS to MDE API |
| `src/library.rs` | Library family — list, upload (multipart), delete library files | HTTPS to MDE API |
| `src/alerts.rs` | Alerts family — list, get, update, batch-update security alerts | HTTPS to MDE API |
| `tests/live_response_flow.rs` | Integration tests for live response flow (7 tests) | in-process mock server only |
| `tests/machines_flow.rs` | Integration tests for machines endpoints (7 tests) | in-process mock server only |
| `tests/machine_actions_flow.rs` | Integration tests for machine action endpoints (7 tests) | in-process mock server only |
| `tests/library_flow.rs` | Integration tests for library endpoints (5 tests) | in-process mock server only |
| `tests/alerts_flow.rs` | Integration tests for alert endpoints (7 tests) | in-process mock server only |
| `tests/manifest_validation.rs` | Endpoint manifest TOML validation (3 tests) | filesystem read only |

`src/lib.rs` defines the crate boundary. Any type or function that downstream
consumers (or integration tests) can reach must be re-exported through one of
the three public modules. This is the place to audit when tightening the public
API surface.

### 4.2 Component Diagram

```text
                         +------------------------+
                         | main.rs                |
                         | - clap::Parser         |
                         | - dispatches to action |
                         +-----------+------------+
                                     |
                                     v
                         +----------------------------+
                         | MdeClient (client.rs)      |
                         | - reqwest::Client          |
                         | - base_url: String         |
                         | - auth: tokio::sync::Mutex |
                         |         <TokenProvider>    |
                         +-----+--------------+------+
                               |              |
                      token    |              | API JSON + bytes
                      refresh  |              |
                               v              v
                   +----------------+   +-----------------------------+
                   | TokenProvider  |   | Endpoint families:          |
                   | (auth.rs)      |   |  - run_live_response()      |
                   +----------------+   |  - machines::*()            |
                                        |  - machine_actions::*()     |
                                        |  - library::*()             |
                                        |  - alerts::*()              |
                                        +-------------+---------------+
                                                      |
                                                      v
                                        +-----------------------------+
                                        | poll_action() (action.rs)   |
                                        | shared polling abstraction  |
                                        +-----------------------------+
```

All endpoint functions are **free functions** that borrow `&MdeClient`, not
methods on it. This keeps transport separate from domain logic and allows the
same client to be reused across multiple endpoint families.

### 4.3 Module Dependency Graph

```text
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

Arrows point from consumer to dependency. Endpoint functions and `MdeClient`
are peers — neither owns the other. `main.rs` is the only module that
coordinates all components. `poll_action()` in `action.rs` is shared between
`live_response` and `machine_actions`. `library` and `alerts` use simpler
request/response patterns (no polling).

## 5. Runtime Flows

### 5.1 Primary GetFile Flow (with types)

```text
User CLI
  |
  | parse args, validate --file when -g
  v
main.rs
  |
  | create TokenProvider + MdeClient
  v
run_live_response(&MdeClient, machine_id, &LiveResponseRequest, Option<&PollConfig>)
  |
  | 1) POST /api/machines/{id}/runliveresponse
  |    sends: LiveResponseRequest (JSON, PascalCase keys)
  |    receives: MachineAction { id, status: Pending }
  |
  | 2) poll GET /api/machineactions/{action_id}
  |    sends: nothing (path only)
  |    receives: MachineAction { id, status }
  |    every config.interval (default 5s) until:
  |      - Succeeded: proceed to step 3
  |      - Failed/Cancelled: return Err with status + action id
  |      - timeout exceeded: return Err with elapsed duration
  |    note: timeout is checked BEFORE each poll request,
  |          not after — a slow response can overshoot the deadline
  |
  | 3) GET /api/machineactions/{id}/GetLiveResponseResultDownloadLink(index=N)
  |    sends: nothing (path only)
  |    receives: DownloadLink { value: "https://blob...?se=...&sig=..." }
  |    repeated once per command in the original request
  |
  | 4) GET SAS URL (raw bytes, no bearer)
  |    sends: nothing (SAS token is in query string)
  |    receives: bytes::Bytes (raw file content or JSON script result)
  v
Ok(Vec<bytes::Bytes>) — one entry per command index
```

### 5.2 Request Authentication and Retry Flow

```text
send_json(method, path, body)
  |
  | bearer_token():
  |   lock tokio::sync::Mutex<TokenProvider>
  |   if token().is_none():
  |     refresh_token() → POST form-encoded to Azure AD
  |   clone token string, release lock
  v
HTTP request with Bearer header
  |
  +--> 2xx: deserialize JSON → Ok(T)
  |
  +--> 401 (first attempt):
  |      force_refresh():
  |        lock Mutex
  |        invalidate() — clears cached token + acquired_at
  |        refresh_token() — acquires fresh token from Azure AD
  |        clone token string, release lock
  |      retry request once with fresh token
  |        |
  |        +--> 2xx: Ok(T)
  |        +--> 401 again: Err(MdeError::Api { status, body })
  |        +--> other status: Err(MdeError::Api { status, body })
  |
  +--> 4xx/5xx (non-401): Err(MdeError::Api { status, body })
  |      response body is read and preserved before checking status,
  |      so MDE's diagnostic error codes are available for debugging.
  |
  +--> network error: Err(MdeError::Network(reqwest::Error))
```

### 5.3 Sequence Diagram: Complete Live Response Interaction

```text
  CLI (main.rs)        MdeClient          TokenProvider        Azure AD         MDE API         Azure Blob
       |                   |                   |                   |                |                |
       |  run_live_response|                   |                   |                |                |
       |------------------>|                   |                   |                |                |
       |                   | bearer_token()    |                   |                |                |
       |                   |------------------>|                   |                |                |
       |                   |                   | token() = None    |                |                |
       |                   |                   | (first call)      |                |                |
       |                   |                   |                   |                |                |
       |                   |                   | POST /token       |                |                |
       |                   |                   | (form-encoded)    |                |                |
       |                   |                   |------------------>|                |                |
       |                   |                   |<------------------|                |                |
       |                   |                   | TokenResponse     |                |                |
       |                   |<------------------|                   |                |                |
       |                   | "Bearer eyJ..."   |                   |                |                |
       |                   |                   |                   |                |                |
       |                   | Step 1: POST runliveresponse          |                |                |
       |                   |-------------------------------------------------->     |                |
       |                   |<--------------------------------------------------     |                |
       |                   | MachineAction { id, status: Pending }                  |                |
       |                   |                   |                   |                |                |
       |                   | Step 2: poll loop |                   |                |                |
       |                   |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>        |                |
       |                   | GET /machineactions/{id}              |                |                |
       |                   |<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~         |                |
       |                   | MachineAction { status: Succeeded }                    |                |
       |                   |                   |                   |                |                |
       |                   | Step 3: GET download link             |                |                |
       |                   |-------------------------------------------------->     |                |
       |                   |<--------------------------------------------------     |                |
       |                   | DownloadLink { value: sas_url }                        |                |
       |                   |                   |                   |                |                |
       |                   | Step 4: GET SAS URL (no Bearer)       |                |                |
       |                   |-----------------------------------------------------------------------> |
       |                   |<----------------------------------------------------------------------- |
       |                   | bytes::Bytes (raw file or script JSON)                 |                |
       |                   |                   |                   |                |                |
       |<------------------|                   |                   |                |                |
       | Ok(Vec<Bytes>)    |                   |                   |                |                |
```

## 6. State Models

### 6.1 Token Lifecycle

The token follows a cyclic state machine. Transitions are driven by time
(expiry), API feedback (401), and explicit calls (refresh, invalidate).

```text
                 ┌────────────────────────────────────────────────┐
                 │                                                │
                 v                                                │
         ┌──────────────┐     refresh_token()      ┌────────────┐ │
    ──>  │   NoToken    │ ───────────────────────> │ ValidToken │ │
         │ token()=None │                          │token()=Some│ │
         └──────────────┘                          └─────┬──────┘ │
                 ^                                       │        │
                 │                                       │        │
                 │  invalidate()          elapsed >=     │        │
                 │  (called on 401)       (expires_in    │        │
                 │                         - 60s)        v        │
                 │                               ┌────────────┐   │
                 └───────────────────────────────│  Expired   │   │
                                                 │token()=None│───┘
                                                 └────────────┘

  Entry states:
    - Construction via new(): starts in NoToken
    - Construction via with_token(): starts in ValidToken (test helper)

  Key invariant:
    - acquired_at is always Some when response is Some
    - acquired_at is always None when response is None
    - is_expired() returns false when no token is cached (NoToken),
      so NoToken and Expired are distinguishable internally but
      both present as token()=None to callers
```

### 6.2 Machine Action Status Lifecycle

```text
Pending ──> InProgress ──> Succeeded
   │             │
   │             └────────> Failed
   └──────────────────────> Cancelled

Unknown (unrecognized API value) is treated as non-terminal during polling.
The poll loop continues until a known terminal status or timeout.
```

The `ActionStatus` enum uses `#[serde(other)]` on the `Unknown` variant, which
means any status string not matching `Pending`, `InProgress`, `Succeeded`,
`Failed`, or `Cancelled` deserializes to `Unknown` instead of causing a parse
error. This provides forward compatibility if Microsoft adds new status values.

## 7. External Interfaces

### 7.1 HTTP Endpoints

| Purpose | Method + Path | Auth mode | Serialization |
|---|---|---|---|
| OAuth2 token | `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | Client credentials form body | `application/x-www-form-urlencoded` via `serde_urlencoded` |
| Start live response | `POST api/machines/{machine_id}/runliveresponse` | Bearer | JSON (PascalCase keys via `#[serde(rename)]`) |
| Poll action status | `GET api/machineactions/{action_id}` | Bearer | JSON response |
| Get command result link | `GET api/machineactions/{action_id}/GetLiveResponseResultDownloadLink(index={i})` | Bearer | JSON response |
| Download result payload | `GET {sas_url}` | SAS query token (no bearer) | Raw bytes |
| List machines | `GET api/machines` | Bearer | JSON response (OData `$filter` in query) |
| Get machine | `GET api/machines/{machine_id}` | Bearer | JSON response |
| Update machine | `PATCH api/machines/{machine_id}` | Bearer | JSON (camelCase keys) |
| Isolate machine | `POST api/machines/{machine_id}/isolate` | Bearer | JSON (PascalCase keys) |
| Unisolate machine | `POST api/machines/{machine_id}/unisolate` | Bearer | JSON (PascalCase keys) |
| AV scan | `POST api/machines/{machine_id}/runAntiVirusScan` | Bearer | JSON (PascalCase keys) |
| Collect investigation | `POST api/machines/{machine_id}/collectInvestigationPackage` | Bearer | JSON (PascalCase keys) |
| Stop & quarantine | `POST api/machines/{machine_id}/StopAndQuarantineFile` | Bearer | JSON (PascalCase keys) |
| Restrict execution | `POST api/machines/{machine_id}/restrictCodeExecution` | Bearer | JSON (PascalCase keys) |
| Unrestrict execution | `POST api/machines/{machine_id}/unrestrictCodeExecution` | Bearer | JSON (PascalCase keys) |
| List library files | `GET api/libraryfiles` | Bearer | JSON response (OData collection) |
| Upload library file | `POST api/libraryfiles` | Bearer | Multipart/form-data |
| Delete library file | `DELETE api/libraryfiles/{fileName}` | Bearer | 204 No Content |
| List alerts | `GET api/alerts` | Bearer | JSON response (OData `$filter` in query) |
| Get alert | `GET api/alerts/{alert_id}` | Bearer | JSON response |
| Update alert | `PATCH api/alerts/{alert_id}` | Bearer | JSON (camelCase keys) |
| Batch update alerts | `PATCH api/alerts/batchUpdate` | Bearer | JSON (camelCase keys), empty response |

### 7.2 CLI Surface (Current)

| Flag | Role | Current behavior |
|---|---|---|
| `--device-id`, `--tenant-id`, `--client-id` | Identity fields | `--tenant-id` and `--client-id` always required; `--device-id` required for device-targeted actions (not library, alert, `--list-machines`, or `-t`) |
| `--secret` / `MDE_CLIENT_SECRET` env var | Client secret for OAuth2 | Required; prefer env var to avoid process-list exposure |
| `-g` + `--file` | GetFile action | Collect a file from the remote device |
| `-r` + `--script` [+ `--args`] | RunScript action | Execute a PowerShell script on the remote device |
| `-p` + `--file` | PutFile action | Upload a file from the MDE library to the remote device |
| `-t` | Token inspection | Acquire an OAuth2 token and print it to stdout |
| `--isolate` + `--comment` [+ `--isolation-type`] | Isolate device | Isolate from network (Full/Selective/UnManagedDevice) |
| `--unisolate` + `--comment` | Unisolate device | Release from network isolation |
| `--scan` + `--comment` [+ `--scan-type`] | AV scan | Run Defender Antivirus scan (Quick/Full) |
| `--collect-investigation` + `--comment` | Forensics | Collect investigation package |
| `--stop-quarantine` + `--comment` + `--sha1` | Quarantine | Stop and quarantine a file by SHA-1 |
| `--restrict-execution` + `--comment` | Restrict apps | Restrict code execution to Microsoft-signed only |
| `--unrestrict-execution` + `--comment` | Unrestrict apps | Remove code execution restrictions |
| `--get-machine` | Device details | Get full details for a specific machine |
| `--list-machines` [+ `--filter`] | Device listing | List machines, optionally filtered by OData expression |
| `--list-library` | List library files | List all Live Response library files |
| `--upload-library` + `--file` [+ `--description`] | Upload library file | Upload a file to the Live Response library (multipart) |
| `--delete-library` + `--file` | Delete library file | Delete a file from the Live Response library |
| `--list-alerts` [+ `--filter`] | List alerts | List security alerts, optionally filtered by OData expression |
| `--get-alert` + `--alert-id` | Get alert | Get full details for a specific alert |
| `--update-alert` + `--alert-id` [+ status/classification/determination/assigned-to/comment] | Update alert | Update an individual alert's triage fields |
| `--batch-update-alerts` + `--alert-ids` [+ status/classification/determination/comment] | Batch update | Update multiple alerts at once |
| `--out` | Output file path | Save downloaded result bytes to disk |
| `--config`, `--query` | Future placeholders | Parsed but currently unused |

**Exit codes:**
- `0`: success
- `1`: runtime error (auth failure, API error, timeout, etc.)
- `2`: argument validation error (clap handles this automatically)

**Action flag constraint:** Exactly one action flag must be set per invocation.
This is enforced at parse time by clap's `#[group(required = true, multiple =
false)]` attribute on `ActionFlags`.

**Machine actions:** Fire-and-forget by default — the CLI prints the action ID
and initial status. Use the action ID in the MDE portal or programmatic polling
to track progress.

**RunScript output handling:** When `-r` is used, the CLI automatically parses
the downloaded bytes as `ScriptResult` JSON and displays the script name, exit
code, stdout, and stderr. If parsing fails (unexpected response format), the
CLI falls back to displaying the raw byte count.

## 8. Reliability and Failure Semantics

### 8.1 Failure Mode Table

| Failure mode | Behavior | Body preserved? |
|---|---|---|
| Token request fails (network/AADSTS) | Error includes HTTP status + raw response body text | Yes — body is read as text before status check |
| API returns 401 (first time) | One forced token refresh + single retry | N/A (retry, not error) |
| API returns 401 (second time) | Hard `MdeError::Api` with status + body | Yes — body preserved |
| API returns non-401 error (403, 404, 500, etc.) | Immediate `MdeError::Api` with status + body | Yes — body preserved |
| Action reaches `Failed` or `Cancelled` | Return error containing status variant + action id | N/A (status-based error) |
| Polling exceeds timeout | Return error including timeout duration + action id | N/A (timeout error) |
| SAS download fails | `MdeError::Api` with status + body, or `MdeError::Network` | Yes — body preserved for HTTP errors |
| Unknown action status during polling | Keep polling until terminal status or timeout | N/A (non-terminal) |
| API returns 429 (throttled) | Read `Retry-After` header, sleep, retry up to `max_retries` times | Yes — body preserved if retries exhausted |
| 429 with `Retry-After` exceeding `max_retry_delay` | Immediate `MdeError::Throttled` (no sleep) | N/A (policy limit) |
| Network error (DNS, TCP, TLS) | Return reqwest transport error | N/A (no response) |

### 8.2 Error Flow Diagram

```text
HTTP Response from MDE API
    │
    ├── 2xx ───────────────> deserialize JSON ──> Ok(T)
    │
    ├── 401 (1st attempt) ─> invalidate token
    │                        refresh token from Azure AD
    │                        retry request once
    │                           │
    │                           ├── 2xx ──────> Ok(T)
    │                           ├── 401 (2nd) ─> Err (MdeError::Api, body preserved)
    │                           ├── 429 ──────> fall through to 429 handling below
    │                           └── other ─────> Err (MdeError::Api, body preserved)
    │
    ├── 429 ─────────────────> read Retry-After header
    │                          if delay > max_retry_delay: Err (MdeError::Throttled)
    │                          sleep(delay), increment retry count
    │                          if retries > max_retries: Err (MdeError::Throttled)
    │                          retry request (loops back to top)
    │
    ├── 4xx/5xx (non-401/429) ─> Err via MdeError::Api { status, body }
    │                            (response body is preserved for diagnostics)
    │
    └── network error ─────────> Err (MdeError::Network wrapping reqwest::Error)
```

## 9. Configuration and Defaults

| Area | Constant / Default | Value | Rationale |
|---|---|---|---|
| Token connect timeout | `TOKEN_CONNECT_TIMEOUT` | 10s | TCP + TLS handshake only; generous for Azure AD |
| Token request timeout | `TOKEN_REQUEST_TIMEOUT` | 30s | Full round-trip; token payloads are small |
| API connect timeout | `API_CONNECT_TIMEOUT` | 10s | TCP + TLS handshake only; generous for Azure services |
| API request timeout | `API_REQUEST_TIMEOUT` | 300s (5 min) | Must accommodate large file downloads via SAS URLs |
| Token expiry safety buffer | `EXPIRY_BUFFER_SECS` | 60s | Prevents edge-of-expiry request failures |
| Poll interval | `PollConfig::default().interval` | 5s | Balances responsiveness against API rate limits |
| Poll timeout | `PollConfig::default().timeout` | 600s (10 min) | Covers long-running scripts; prevents infinite hangs |
| Throttle max retries | `RetryPolicy::default().max_retries` | 3 | Most transient throttling resolves in 1-2 retries |
| Throttle max delay | `RetryPolicy::default().max_retry_delay` | 60s | Prevents a single request from blocking for minutes |

**Why separate timeout profiles?** Token requests and API requests have very
different payload sizes and server-side processing times. Token requests are
small form-encoded POST/responses (~1KB) that Azure AD processes in <500ms.
API requests may involve downloading multi-MB file results through SAS URLs.
Using a single timeout would either be too aggressive for downloads or too
lenient for token failures.

## 10. Testing Strategy and Coverage

### 10.1 Test Layers

| Test layer | Scope | Notable assertions |
|---|---|---|
| Unit tests in `src/auth.rs` (11 tests) | Token URL construction, serde, cache expiry/buffer logic | Token invalid before refresh, expiry is deterministic, buffer boundary behavior |
| Unit tests in `src/client.rs` (12 tests) | HTTP methods (GET/POST/PUT/PATCH/DELETE), 401 retry, 429 throttle retry, error body preservation, SAS download, multipart upload | One-shot 401 retry, 429 retry with Retry-After, retry exhaustion, max delay cap, PATCH/DELETE/multipart happy paths |
| Unit tests in `src/error.rs` (8 tests) | Error display, source chaining, Send+Sync, Throttled variant | All variants display correctly, source chain traversable, Throttled displays retry-after |
| Unit tests in `src/action.rs` (7 tests) | ActionStatus serde, MachineAction deserialization, PollConfig defaults | Forward-compatible enum parsing, optional field handling, full response deserialization |
| Unit tests in `src/live_response.rs` (3 tests) | LiveResponse-specific model serde and request round-trips | PascalCase serialization, PutFile variant |
| Unit tests in `src/machines.rs` (7 tests) | Machine serde, ODataList, UpdateMachineRequest serialization | Full/minimal/unknown-fields deserialization, optional field defaults, skip-if-none serialization |
| Unit tests in `src/machine_actions.rs` (7 tests) | Request type serialization for all 7 endpoints | PascalCase keys match MDE API contract, no snake_case leaks |
| Unit tests in `src/library.rs` (4 tests) | LibraryFile deserialization (full, minimal, unknown fields, ODataList) | camelCase field mapping, optional field defaults, forward compatibility |
| Unit tests in `src/alerts.rs` (9 tests) | Alert deserialization, UpdateAlertRequest/BatchUpdateAlertsRequest serialization | Full/minimal/unknown-fields Alert, ODataList, skip-if-none serialization, batch request format |
| Unit tests in `src/main.rs` (35 tests) | CLI argument parsing for all 21 action flags, output path indexing | Action flag enforcement, parameter validation, conflicting flags rejected, library/alert flags |
| Integration tests in `tests/live_response_flow.rs` (7 tests) | Full 4-step wiremock flow | End-to-end bytes returned, RunScript parse path, failed/cancelled actions, polling timeout, multi-step progression, multi-command indexing |
| Integration tests in `tests/machines_flow.rs` (7 tests) | Machines family with wiremock | List with/without filter, empty list, get success, get 404, update both fields, update tags only |
| Integration tests in `tests/machine_actions_flow.rs` (7 tests) | Machine actions with wiremock | Isolate poll-to-success, unisolate fire-and-forget, AV scan progression, investigation failure, quarantine, restrict/unrestrict, 400 API error |
| Integration tests in `tests/library_flow.rs` (5 tests) | Library family with wiremock | List (2 files), list empty, upload multipart, delete 204, delete 404 |
| Integration tests in `tests/alerts_flow.rs` (7 tests) | Alerts family with wiremock | List, list with filter, get full alert, get 404, update all fields, update comment only, batch update |
| Integration tests in `tests/manifest_validation.rs` (3 tests) | Endpoint manifest TOML validation | Schema structure, 21 implemented endpoints, valid HTTP verbs |

### 10.2 How the Mock Server Works

Integration tests use `wiremock::MockServer` to replace **both** the MDE API
and Azure Blob Storage. This works because:

1. `MdeClient::with_base_url()` redirects all API calls to the mock server's
   URL instead of `api.security.microsoft.com`.
2. The mock for `GetLiveResponseResultDownloadLink` returns a SAS URL that
   **also** points to the mock server (e.g. `http://127.0.0.1:{port}/blob/result.zip`).
3. Since `MdeClient::download()` uses the same `reqwest::Client` for SAS
   downloads, these requests also hit the mock server.

This means all four steps of the live response flow execute against a single
in-process HTTP server, with no network calls to real Azure services.

### 10.3 Test Ergonomics and Known Limitations

- **`TokenProvider::with_token()`** bypasses Azure AD entirely by pre-setting a
  token with a 1-hour expiry. Tests never trigger real OAuth2 flows.
- **`PollConfig`** is passed as `None` in all current integration tests, which
  means the default 5-second poll interval applies. The first poll response
  returns `Succeeded` immediately, so the test only sleeps once (5s). Tests
  that need to exercise the timeout path should pass a custom `PollConfig` with
  a short interval and timeout.
- **401 retry path is tested in `client.rs` unit tests.** Two tests cover
  the retry behavior: `send_json_retries_once_on_401_then_succeeds` and
  `send_json_returns_api_error_after_double_401`. These use wiremock with
  a mock token endpoint via `test_client_with_token_endpoint()`.

## 11. Key Design Decisions

| ID | Decision | Why | Where |
|---|---|---|---|
| D-001 | `MdeClient` owns `tokio::sync::Mutex<TokenProvider>` (not `std::sync::Mutex`) | `tokio::sync::Mutex` can be held across `.await` points. Needed because `refresh_token()` is async. `std::sync::Mutex` would panic or deadlock if held across an await. | `src/client.rs` |
| D-002 | Mutex lock is released before HTTP calls | The lock is acquired to check/refresh the token, the token string is cloned out, and the lock is dropped. This prevents the mutex from serializing all concurrent API calls behind a single lock. | `src/client.rs` (`bearer_token`, `force_refresh`) |
| D-003 | `send_json<T, B>` generic request helper | Keeps method-specific wrappers (`get`, `post`, `put`) thin and consistent. Single place to implement retry logic. | `src/client.rs` |
| D-004 | One-shot retry on 401, bounded retry on 429 | 401 handles revoked/stale tokens (one retry). 429 honors `Retry-After` header up to `RetryPolicy::max_retries` (default 3). Both compose: a 401 retry can itself hit 429. Non-401/429 errors propagate immediately. | `src/client.rs` |
| D-005 | `ActionStatus::Unknown` enum variant with `#[serde(other)]` | Avoids hard deserialization failures if Microsoft adds new status values. Unknown is treated as non-terminal during polling. | `src/action.rs` |
| D-006 | Separate token/API timeout profiles | Token requests are small/fast; result downloads may be large. A single timeout can't serve both well. | `src/auth.rs`, `src/client.rs` |
| D-007 | All endpoint functions are free functions, not methods on `MdeClient` | Keeps orchestration logic separate from the HTTP client. The client is a reusable transport layer; orchestration is a higher-level concern. Each endpoint family is a separate module with its own free functions. | `src/live_response.rs`, `src/machines.rs`, `src/machine_actions.rs` |
| D-008 | `with_token` + `with_base_url` test constructors | Enable deterministic tests without real cloud dependencies. Separate from production constructors to avoid polluting the public API. | `src/auth.rs`, `src/client.rs` |
| D-009 | `RetryPolicy` is a separate configurable struct, not hardcoded | Different callers need different retry budgets. Tests use aggressive settings (0s delay); production defaults to 3 retries with 60s cap. | `src/client.rs` |
| D-010 | `send_no_content` parallel to `send_json` for 204 responses | DELETE and some POST endpoints return empty bodies. Attempting JSON deserialization on 204 would fail. Separate method avoids conditional logic in `parse_response`. | `src/client.rs` |
| D-011 | Multipart uploads skip 401/429 retry | `reqwest::multipart::Form` is consumed on send (not `Clone`). Buffering form parts for replay adds complexity with little benefit since uploads are infrequent, user-initiated operations. | `src/client.rs` |
| D-012 | Endpoint manifest as TOML, validated in CI | Tracks API coverage as structured data rather than prose. CI test catches syntax errors and missing fields. Manifest is the foundation for future codegen. | `manifest/endpoints.toml`, `tests/manifest_validation.rs` |
| D-013 | `patch_no_content` for PATCH with empty response | The batch-update-alerts endpoint returns 200 with empty body. `send_json` would fail trying to deserialize JSON from an empty response. `send_json_no_content` combines JSON request body with empty-response handling. | `src/client.rs` |
| D-014 | Alert evidence as `Vec<serde_json::Value>` | MDE evidence objects are polymorphic (file, process, IP, etc.) with different schemas per type. Full typing is deferred until concrete use cases emerge; `serde_json::Value` provides forward compatibility. | `src/alerts.rs` |

## 12. Codegen Boundary

The endpoint manifest (`manifest/endpoints.toml`) establishes the boundary between
handwritten and generated code. As of Milestone 0, no code is generated — the
manifest is read-only metadata validated in CI.

| Layer | Approach | Rationale |
|-------|----------|-----------|
| Auth, transport, error types | Handwritten (always) | Complex control flow (retry, mutex, expiry) that benefits from explicit implementation |
| Retry logic (401, 429) | Handwritten (always) | State-dependent behavior with composition (401 can trigger 429) |
| Orchestration (polling, multi-step flows) | Handwritten (always) | Domain-specific logic that varies per endpoint family |
| CLI argument parsing | Handwritten (always) | User-facing surface that benefits from careful documentation |
| Endpoint inventory, permissions | Manifest-driven (now) | Structured data that should be validated and tracked systematically |
| Coverage tracking | Manifest-driven (now) | `implemented` flag in manifest drives CI reports |
| Endpoint function stubs | Generated (future, M1+) | Repetitive boilerplate (URL construction, type aliases) once patterns stabilize |
| Request/response type scaffolds | Generated (future, M1+) | Can be derived from manifest once enough families are implemented by hand |

The generation boundary will shift as more endpoint families are implemented. The
guiding principle: implement at least two families by hand before extracting
patterns into generated code. This ensures the abstractions match real usage, not
hypothetical shapes.

## 13. Current Gaps and Next Architectural Steps

| Gap | Impact | Suggested direction |
|---|---|---|
| No structured logging/tracing | Harder production debugging of polling and retries | Add `tracing` spans around auth, poll loop, and downloads |
| Results are fully buffered in memory before writing to disk | Large downloads increase memory pressure | Add optional streaming write-to-disk path (currently `--out` writes after full buffering) |
| Workspace split | Single crate serves both CLI and library consumers | Split into `mde-lr` (CLI binary) and `mde-lr-lib` (library crate) when a second consumer emerges |
| 11 unimplemented endpoints | 66% API coverage | Milestone 3 (hunting + indicators), M4 (broad rollout) |

Resolved gaps (completed in Phases 1-4, Milestone 0, and Milestone 1):
- Typed `MdeError` enum with source chaining (Phase 2a)
- Configurable cloud endpoints for sovereign clouds (Phase 2b)
- `#![warn(missing_docs)]` enabled (Phase 2c)
- 401 retry integration tests with wiremock (Phase 3b)
- All three Live Response actions implemented: GetFile, RunScript, PutFile (Phase 4)
- Full HTTP verb coverage: PATCH, DELETE, multipart upload (M0)
- 204 No Content handling for delete endpoints (M0)
- 429 throttle retry with configurable `RetryPolicy` and `Retry-After` header (M0)
- Endpoint manifest with CI validation (M0)
- Shared action-polling abstraction extracted for cross-family reuse (M1)
- Machines family: list, get, update with OData filtering (M1)
- Machine Actions family: 7 incident response endpoints (M1)
- CLI expanded with 9 new action flags (M1)
- Library family: list, upload (multipart), delete (M2)
- Alerts family: list, get, update, batch-update (M2)
- CLI expanded with 8 new action flags + 7 supporting params (M2)

## 13. Inspiration Notes

This document follows an RFD-like style: explicit constraints, decision records,
clear state/flow diagrams, and operational semantics before implementation
details. Style references reviewed:

- https://rfd.shared.oxide.computer/
- https://github.com/oxidecomputer
