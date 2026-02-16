# mde-lr Architecture

Status: Draft
Owner: mde-lr maintainers
Last updated: 2026-02-14

## 1. Purpose and Scope

This document explains how `mde-lr` is built today: module boundaries,
runtime flow, failure semantics, and key design choices.

`mde-lr` is an async Rust CLI that executes Microsoft Defender for Endpoint
(MDE) Live Response actions against a target device. The implemented CLI path
today is `GetFile`; the core orchestration is generic enough to support
`RunScript` and multi-command sessions.

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
| Polling must terminate | Prevent infinite hangs | `src/live_response.rs` (`PollConfig.timeout`) |
| Unknown action statuses must not crash deserialization | Forward compatibility with API changes | `ActionStatus::Unknown` with `#[serde(other)]` |
| SAS download must not attach bearer auth | SAS URL already carries authorization via query-string token | `MdeClient::download` |
| Token endpoint uses form-encoded bodies, not JSON | Azure AD `/oauth2/v2.0/token` requires `application/x-www-form-urlencoded` | `src/auth.rs` (`reqwest::RequestBuilder::form()` serializes via `serde_urlencoded`) |
| Public API surface returns fallible async results | Explicit failure handling across network boundaries | `Result<T, Box<dyn Error + Send + Sync>>` convention |

## 4. Module Architecture

### 4.1 Code Layout

| Module | Responsibility | External side effects |
|---|---|---|
| `src/lib.rs` | Crate root — re-exports `auth`, `client`, and `live_response` as the public API surface | None (module declaration only) |
| `src/main.rs` | CLI parsing and command dispatch | stdout/stderr, process exit code |
| `src/auth.rs` | OAuth2 token acquisition + cache lifecycle | HTTPS to Azure AD token endpoint |
| `src/client.rs` | Authenticated HTTP wrapper and retry behavior | HTTPS to MDE API and SAS URLs |
| `src/live_response.rs` | Live Response request/response models + orchestration | Polling loop + downloads |
| `tests/live_response_flow.rs` | Integration behavior tests over mock HTTP | in-process mock server only |

`src/lib.rs` defines the crate boundary. Any type or function that downstream
consumers (or integration tests) can reach must be re-exported through one of
the three public modules. This is the place to audit when tightening the public
API surface.

### 4.2 Component Diagram

```text
                         +------------------------+
                         | main.rs                |
                         | - clap::Parser         |
                         | - builds request       |
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
                   +----------------+   +------------------------+
                   | TokenProvider  |   | run_live_response()    |
                   | (auth.rs)      |   | (live_response.rs)     |
                   +----------------+   | free function, borrows |
                                        | &MdeClient             |
                                        +------------------------+
```

Note that `run_live_response` is a **free function** that borrows `&MdeClient`,
not a method on `MdeClient`. This is a deliberate composability choice: the
orchestration logic depends on the client's capabilities but doesn't own it,
allowing the same client to be reused across multiple orchestration calls.

### 4.3 Module Dependency Graph

```text
main.rs ──> MdeClient ──> TokenProvider
   │            │
   │            └──> reqwest::Client
   │
   └──> run_live_response() ──> MdeClient (via &self)
```

Arrows point from consumer to dependency. `run_live_response` and `MdeClient`
are peers — neither owns the other. `main.rs` is the only module that
coordinates all three.

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
  |        +--> 401 again: Err (hard failure, no further retries)
  |        +--> other status: Err (error_for_status)
  |
  +--> 4xx/5xx (non-401): Err via error_for_status()
  |      NOTE: error_for_status() discards the response body.
  |      For non-401 API errors, the raw error body from MDE is lost.
  |      This is a known limitation — typed errors (Phase 2) will
  |      preserve the body for diagnostics.
  |
  +--> network error: Err (reqwest transport error)
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

### 7.2 CLI Surface (Current)

| Flag | Role | Current behavior |
|---|---|---|
| `--device-id`, `--tenant-id`, `--client-id` | Required identity fields | Required for execution |
| `--secret` / `MDE_CLIENT_SECRET` env var | Client secret for OAuth2 | Required; prefer env var to avoid process-list exposure |
| `-g` + `--file` | GetFile action | Implemented end-to-end; `--file` is validated at runtime when `-g` is set |
| `--config`, `--query` | Future placeholders | Parsed but currently unused |

**Exit codes:**
- `0`: success
- `1`: runtime error (auth failure, API error, timeout, etc.)
- `2`: argument validation error (clap handles this automatically)

**Action flag constraint:** Exactly one of `-g`, `-p`, `-d` must be set per
invocation. This is enforced at parse time by clap's `#[group(required = true,
multiple = false)]` attribute on `ActionFlags`.

## 8. Reliability and Failure Semantics

### 8.1 Failure Mode Table

| Failure mode | Behavior | Body preserved? |
|---|---|---|
| Token request fails (network/AADSTS) | Error includes HTTP status + raw response body text | Yes — body is read as text before status check |
| API returns 401 (first time) | One forced token refresh + single retry | N/A (retry, not error) |
| API returns 401 (second time) | Hard error via `error_for_status()` | No — body discarded |
| API returns non-401 error (403, 404, 500, etc.) | Immediate error via `error_for_status()` | No — body discarded |
| Action reaches `Failed` or `Cancelled` | Return error containing status variant + action id | N/A (status-based error) |
| Polling exceeds timeout | Return error including timeout duration + action id | N/A (timeout error) |
| SAS download fails | Return HTTP error from download request | No — body discarded |
| Unknown action status during polling | Keep polling until terminal status or timeout | N/A (non-terminal) |
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
    │                           ├── 401 (2nd) ─> Err (hard failure)
    │                           └── other ─────> Err (error_for_status)
    │
    ├── 4xx/5xx (non-401) ─> Err via error_for_status()
    │                        (response body is discarded — known limitation)
    │
    └── network error ─────> Err (reqwest transport error)
```

**Known limitation:** `error_for_status()` discards the HTTP response body. For
non-401 API errors, the detailed error message from MDE (which can include
diagnostic codes and human-readable explanations) is lost. The planned typed
error enum (Phase 2) will read the body before checking status, matching the
pattern already used in `auth.rs` for token errors.

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
| Unit tests in `src/auth.rs` | Token URL construction, serde, cache expiry/buffer logic | Token invalid before refresh, expiry is deterministic, buffer boundary behavior |
| Unit tests in `src/live_response.rs` | API model serde, unknown status handling, poll defaults, request round-trips | Forward-compatible enum parsing, PascalCase serialization |
| Integration tests in `tests/live_response_flow.rs` | Full 4-step wiremock flow | End-to-end bytes returned, RunScript parse path, failed action error, multi-command indexing |

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
- **No tests for 401 retry path yet.** The `send_json` retry logic is
  implemented but not covered by integration tests. This is tracked as a
  Phase 3 gap.

## 11. Key Design Decisions

| ID | Decision | Why | Where |
|---|---|---|---|
| D-001 | `MdeClient` owns `tokio::sync::Mutex<TokenProvider>` (not `std::sync::Mutex`) | `tokio::sync::Mutex` can be held across `.await` points. Needed because `refresh_token()` is async. `std::sync::Mutex` would panic or deadlock if held across an await. | `src/client.rs` |
| D-002 | Mutex lock is released before HTTP calls | The lock is acquired to check/refresh the token, the token string is cloned out, and the lock is dropped. This prevents the mutex from serializing all concurrent API calls behind a single lock. | `src/client.rs` (`bearer_token`, `force_refresh`) |
| D-003 | `send_json<T, B>` generic request helper | Keeps method-specific wrappers (`get`, `post`, `put`) thin and consistent. Single place to implement retry logic. | `src/client.rs` |
| D-004 | One-shot retry only on 401 | Handles revoked/stale tokens without risking retry loops. Non-401 errors are never retried because they indicate a real problem (bad request, server error), not a stale credential. | `src/client.rs` |
| D-005 | `ActionStatus::Unknown` enum variant with `#[serde(other)]` | Avoids hard deserialization failures if Microsoft adds new status values. Unknown is treated as non-terminal during polling. | `src/live_response.rs` |
| D-006 | Separate token/API timeout profiles | Token requests are small/fast; result downloads may be large. A single timeout can't serve both well. | `src/auth.rs`, `src/client.rs` |
| D-007 | `run_live_response` is a free function, not a method on `MdeClient` | Keeps orchestration logic separate from the HTTP client. The client is a reusable transport layer; orchestration is a higher-level concern. This supports future API families without bloating `MdeClient`. | `src/live_response.rs` |
| D-008 | `with_token` + `with_base_url` test constructors | Enable deterministic tests without real cloud dependencies. Separate from production constructors to avoid polluting the public API. | `src/auth.rs`, `src/client.rs` |

## 12. Current Gaps and Next Architectural Steps

| Gap | Impact | Suggested direction | Plan phase |
|---|---|---|---|
| Only `-g` (GetFile) action implemented | CLI supports one action type | Add `-p` (PutFile) and RunScript flags when execution paths are ready | — |
| No structured logging/tracing | Harder production debugging of polling and retries | Add `tracing` spans around auth, poll loop, and downloads | — |
| Boxed dynamic errors everywhere | Coarse error taxonomy for callers; response bodies lost on non-401 errors | Introduce typed `MdeError` enum with source chaining | Phase 2a |
| Results are fully buffered in memory | Large downloads increase memory pressure | Add optional streaming write-to-disk path | — |
| No 401 retry integration tests | Retry logic is implemented but untested end-to-end | Add wiremock tests with staged 401 → success responses | Phase 3b |
| Hardcoded cloud endpoints | Cannot target sovereign/government clouds | Make token URL and API base URL configurable via constructors | Phase 2b |
| No `#![warn(missing_docs)]` | Public API can drift without documentation | Enable after public surface is stabilized | Phase 2c |

## 13. Inspiration Notes

This document follows an RFD-like style: explicit constraints, decision records,
clear state/flow diagrams, and operational semantics before implementation
details. Style references reviewed:

- https://rfd.shared.oxide.computer/
- https://github.com/oxidecomputer
