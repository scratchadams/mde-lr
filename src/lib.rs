//! Async Rust client library for Microsoft Defender for Endpoint (MDE) Live Response.
//!
//! Provides OAuth2 authentication, an authenticated HTTP client with 401 retry,
//! and a 4-step orchestration function for executing Live Response actions
//! (GetFile, RunScript) against managed devices.
//!
//! # Modules
//!
//! - [`action`] — Shared machine-action types and polling abstraction.
//! - [`auth`] — OAuth2 client credentials token provider with expiry tracking.
//! - [`client`] — Authenticated HTTP wrapper for the MDE REST API.
//! - [`error`] — Typed error hierarchy (`MdeError`) for all library operations.
//! - [`live_response`] — Request/response types and end-to-end orchestration.
//! - [`machine_actions`] — Remediation actions (isolate, scan, quarantine, etc.).
//! - [`machines`] — Device lookup, listing, and property updates.
//!
//! # Quick Start
//!
//! ```ignore
//! use mde_lr::auth::TokenProvider;
//! use mde_lr::client::MdeClient;
//! use mde_lr::live_response::{
//!     Command, CommandType, LiveResponseRequest, Param, run_live_response,
//! };
//!
//! let tp = TokenProvider::new("tenant", "client_id", "secret", "scope");
//! let client = MdeClient::new(tp, None).await;
//! let request = LiveResponseRequest { /* ... */ };
//! let results = run_live_response(&client, "device-id", &request, None).await?;
//! ```

#![warn(missing_docs)]

pub mod action;
pub mod auth;
pub mod client;
pub mod error;
pub mod live_response;
pub mod machine_actions;
pub mod machines;
