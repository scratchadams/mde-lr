# Endpoint Manifest

This directory contains the MDE API endpoint inventory used for tracking
implementation coverage and (in future milestones) generating endpoint stubs.

## Schema

`endpoints.toml` uses a simple TOML schema:

```toml
[meta]
schema_version = 1         # Increment when the schema changes
last_validated = "YYYY-MM-DD"

[[endpoints]]
family = "live_response"   # Logical grouping (live_response, library, alerts, etc.)
name = "run_live_response" # Unique identifier within the family
method = "POST"            # HTTP method (GET, POST, PUT, PATCH, DELETE)
path = "/api/..."          # URL path template with {placeholders}
request_content_type = "application/json"  # Or "multipart/form-data", or "" for no body
response_status = 200      # Expected success status code (200, 201, 204)
permissions = ["Perm.Name"] # Required Azure AD application permissions
implemented = true         # Whether this endpoint has a working implementation
notes = "..."              # Optional free-text notes
```

## Validation

The manifest is validated in CI via a Rust test that deserializes the TOML file
and checks structural correctness. Run it with:

```bash
cargo test manifest_endpoints_toml_is_valid
```

This ensures the manifest stays syntactically valid as endpoints are added or
modified. Semantic validation (checking against upstream MDE documentation) is
planned for a future milestone.

## Adding an Endpoint

1. Add a new `[[endpoints]]` entry to `endpoints.toml` with all required fields.
2. Set `implemented = false` until the endpoint has a working implementation
   with tests.
3. Run `cargo test manifest_endpoints_toml_is_valid` to verify the entry parses.
4. When the implementation is complete and tested, set `implemented = true`.

## Codegen Boundary

The manifest is currently read-only metadata — no code is generated from it.
The boundary between handwritten and generated code is:

- **Handwritten** (always): auth, client transport, error types, retry logic,
  orchestration (polling loops), CLI argument parsing.
- **Manifest-driven** (now): endpoint inventory, permission mappings, coverage
  tracking, CI validation.
- **Generated** (future, Milestone 1+): endpoint function stubs, request/response
  type scaffolds, permission documentation.

The generation boundary will be established when a second endpoint family
(beyond Live Response) is implemented, providing enough examples to identify
the repeatable patterns worth generating.
