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

## 2. System Context

```text
+---------------------------+          +----------------------------------+
| Operator / Automation     |  CLI     | mde-lr process                   |
| (terminal, CI, scripts)   +--------->| - clap arg parsing               |
+---------------------------+          | - auth token cache/refresh       |
                                       | - MDE API orchestration          |
                                       +----------------+-----------------+
                                                        |
                                   HTTPS (Bearer token)|
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
                                       | downloaded result payload      |
                                       +-------------------------------+

Separate auth dependency:
  mde-lr -> login.microsoftonline.com (OAuth2 client_credentials)
```

## 3. Design Constraints and Invariants

| Constraint / Invariant | Why it exists | Where enforced |
|---|---|---|
| API calls must carry valid bearer token | MDE API requires OAuth2 app auth | `src/client.rs` (`bearer_token`, `send_json`) |
| Cached token must refresh before hard expiry | Avoid edge-of-expiry failures | `src/auth.rs` (`EXPIRY_BUFFER_SECS=60`, `is_expired`) |
| Polling must terminate | Prevent infinite hangs | `src/live_response.rs` (`PollConfig.timeout`) |
| Unknown action statuses must not crash deserialization | Forward compatibility with API changes | `ActionStatus::Unknown` with `#[serde(other)]` |
| SAS download must not attach bearer auth | SAS URL already carries authorization | `MdeClient::download` |
| Public API surface returns fallible async results | Explicit failure handling across network boundaries | `Result<T, Box<dyn Error + Send + Sync>>` convention |

## 4. Module Architecture

### 4.1 Code Layout

| Module | Responsibility | External side effects |
|---|---|---|
| `src/main.rs` | CLI parsing and command dispatch | stdout/stderr, process exit code |
| `src/auth.rs` | OAuth2 token acquisition + cache lifecycle | HTTPS to Azure AD token endpoint |
| `src/client.rs` | Authenticated HTTP wrapper and retry behavior | HTTPS to MDE API and SAS URLs |
| `src/live_response.rs` | Live Response request/response models + orchestration | Polling loop + downloads |
| `tests/live_response_flow.rs` | Integration behavior tests over mock HTTP | in-process mock server only |

### 4.2 Component Diagram

```text
                         +------------------------+
                         | main.rs                |
                         | - clap::Parser         |
                         | - builds request       |
                         +-----------+------------+
                                     |
                                     v
                         +------------------------+
                         | MdeClient (client.rs)  |
                         | - reqwest::Client      |
                         | - base_url             |
                         | - Mutex<TokenProvider> |
                         +-----+--------------+---+
                               |              |
                      token    |              | API JSON + bytes
                      refresh  |              |
                               v              v
                   +----------------+   +------------------------+
                   | TokenProvider  |   | run_live_response      |
                   | (auth.rs)      |   | (live_response.rs)     |
                   +----------------+   +------------------------+
```

## 5. Runtime Flows

### 5.1 Primary GetFile Flow

```text
User CLI
  |
  | parse args, validate --file when -g
  v
main.rs
  |
  | create TokenProvider + MdeClient
  v
run_live_response()
  |
  | 1) POST /api/machines/{id}/runliveresponse
  |    -> action id
  |
  | 2) poll GET /api/machineactions/{action_id}
  |    every interval until:
  |      - Succeeded: continue
  |      - Failed/Cancelled: error
  |      - timeout: error
  |
  | 3) GET /api/machineactions/{id}/GetLiveResponseResultDownloadLink(index=N)
  |    -> SAS URL
  |
  | 4) GET SAS URL (raw bytes, no bearer)
  v
bytes::Bytes results (1 result per command index)
```

### 5.2 Request Authentication and Retry Flow

```text
send_json(method, path, body)
  |
  | acquire token from TokenProvider
  |   - refresh if missing/expired
  v
HTTP request with bearer auth
  |
  +--> non-401: return status/error_for_status result
  |
  +--> 401:
        invalidate token
        refresh token once
        retry once
        |
        +--> success: return
        +--> second 401 or other error: return error
```

## 6. State Models

### 6.1 Token Lifecycle

```text
 [NoToken]
     |
     | refresh_token()
     v
 [ValidToken] --elapsed >= (expires_in - 60s)--> [ExpiredLogical]
     |                                             |
     | invalidate() (on 401)                       | token() returns None
     +---------------------------------------------+
```

### 6.2 Machine Action Status Lifecycle

```text
Pending --> InProgress --> Succeeded
   |            |
   |            +--------> Failed
   +---------------------> Cancelled

Unknown (future API value) is treated as non-terminal in polling.
```

## 7. External Interfaces

### 7.1 HTTP Endpoints

| Purpose | Method + Path | Auth mode |
|---|---|---|
| OAuth2 token | `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | Client credentials form body |
| Start live response | `POST api/machines/{machine_id}/runliveresponse` | Bearer |
| Poll action status | `GET api/machineactions/{action_id}` | Bearer |
| Get command result link | `GET api/machineactions/{action_id}/GetLiveResponseResultDownloadLink(index={i})` | Bearer |
| Download result payload | `GET {sas_url}` | SAS query token (no bearer) |

### 7.2 CLI Surface (Current)

| Flag | Role | Current behavior |
|---|---|---|
| `--device-id`, `--tenant-id`, `--client-id`, `--secret` | Required identity/auth fields | Required for execution |
| `-g` / `--file` | GetFile action | Implemented end-to-end |
| `-p`, `-d` | Action placeholders | Parsed but no execution path yet |
| `--config`, `--query` | Future placeholders | Parsed but currently unused |

## 8. Reliability and Failure Semantics

| Failure mode | Behavior |
|---|---|
| Token request fails (network/AADSTS) | Bubble up with status + raw response body |
| API returns non-2xx (except first 401) | Immediate error via `error_for_status()` |
| API returns 401 | One forced token refresh + single retry |
| Action reaches `Failed` or `Cancelled` | Return explicit error containing status + action id |
| Polling exceeds timeout | Return timeout error including elapsed config |
| SAS download fails | Return HTTP error from download request |
| Unknown action status | Keep polling until terminal status or timeout |

## 9. Configuration and Defaults

| Area | Constant / Default | Value |
|---|---|---|
| Token connect timeout | `TOKEN_CONNECT_TIMEOUT` | 10s |
| Token request timeout | `TOKEN_REQUEST_TIMEOUT` | 30s |
| API connect timeout | `API_CONNECT_TIMEOUT` | 10s |
| API request timeout | `API_REQUEST_TIMEOUT` | 300s |
| Token expiry safety buffer | `EXPIRY_BUFFER_SECS` | 60s |
| Poll interval | `PollConfig::default().interval` | 5s |
| Poll timeout | `PollConfig::default().timeout` | 600s |

## 10. Testing Strategy and Coverage

| Test layer | Scope | Notable assertions |
|---|---|---|
| Unit tests in `src/auth.rs` | Token URL construction, serde, cache expiry/buffer logic | Token invalid before refresh, expiry behavior is deterministic |
| Unit tests in `src/live_response.rs` | API model serde, unknown status handling, poll defaults | Forward-compatible enum parsing |
| Integration tests in `tests/live_response_flow.rs` | Full 4-step wiremock flow | End-to-end bytes returned, RunScript parse path, failed action error, multi-command indexing |

## 11. Key Design Decisions

| ID | Decision | Why |
|---|---|---|
| D-001 | `MdeClient` owns `Mutex<TokenProvider>` | Allows `&self` request APIs while preserving mutable token refresh |
| D-002 | `send_json<T, B>` generic request helper | Keeps method-specific wrappers thin and consistent |
| D-003 | One-shot retry only on 401 | Handles revoked/stale token without risking retry loops |
| D-004 | `ActionStatus::Unknown` enum variant | Avoids hard failures if Microsoft adds new status values |
| D-005 | Separate token/API timeout profiles | Token requests are small/fast; result downloads may be large |
| D-006 | `with_token` + `with_base_url` test constructors | Enable deterministic tests without real cloud dependencies |

## 12. Current Gaps and Next Architectural Steps

| Gap | Impact | Suggested direction |
|---|---|---|
| `-p` and `-d` flags are not implemented | CLI surface suggests capabilities that do not execute | Either implement handlers or remove flags until ready |
| No structured logging/tracing | Harder production debugging of polling and retries | Add `tracing` spans around auth, poll loop, and downloads |
| Boxed dynamic errors everywhere | Coarse error taxonomy for callers | Introduce typed error enum with source chaining |
| Results are fully buffered in memory | Large downloads can increase memory pressure | Add optional streaming write-to-disk path |

## 13. Inspiration Notes

This document follows an RFD-like style: explicit constraints, decision records,
clear state/flow diagrams, and operational semantics before implementation
details. Style references reviewed:

- https://rfd.shared.oxide.computer/
- https://github.com/oxidecomputer
