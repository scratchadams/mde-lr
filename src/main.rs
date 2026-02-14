//! CLI entry point for mde-lr — a Microsoft Defender for Endpoint Live Response client.
//!
//! Authenticates via OAuth2 client credentials, then dispatches to the
//! appropriate MDE API action based on CLI flags (`-g` for GetFile, etc.).
//!
//! Exit codes:
//! - 0: success
//! - 1: runtime error (auth failure, API error, timeout, etc.)
//! - 2: argument validation error (clap handles this automatically)

use std::process::ExitCode;

use clap::Parser;

use mde_lr::auth::TokenProvider;
use mde_lr::client::MdeClient;
use mde_lr::live_response::{Command, CommandType, LiveResponseRequest, Param, run_live_response};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Remote file path (required for GetFile commands).
    #[arg(long)]
    file: Option<std::path::PathBuf>,

    #[arg(long)]
    config: Option<std::path::PathBuf>,

    /// MDE device ID to target for live response actions.
    #[arg(long)]
    device_id: String,

    /// Azure AD tenant ID for OAuth2 authentication.
    #[arg(long)]
    tenant_id: String,

    /// Azure AD application (client) ID.
    #[arg(long)]
    client_id: String,

    /// Azure AD client secret. Prefer setting via the MDE_CLIENT_SECRET
    /// environment variable to avoid exposing the secret in process listings
    /// and shell history.
    #[arg(long, env = "MDE_CLIENT_SECRET")]
    secret: String,

    #[arg(long)]
    query: Option<bool>,

    #[command(flatten)]
    actions: ActionFlags,
}

/// Action flags — exactly one must be set per invocation.
///
/// Clap enforces this at parse time via the `group` attribute:
/// - If none are set, clap prints an error and exits with code 2.
/// - If more than one is set, clap prints an error and exits with code 2.
#[derive(clap::Args)]
#[group(required = true, multiple = false)]
struct ActionFlags {
    #[arg(short)]
    put: bool,

    /// Collect a file from the remote device via Live Response GetFile.
    #[arg(short)]
    get: bool,

    #[arg(short)]
    download: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Cli::parse();

    println!("DeviceID: {}", args.device_id);
    let tp = TokenProvider::new(
        &args.tenant_id,
        &args.client_id,
        &args.secret,
        "https://api.securitycenter.microsoft.com/.default",
    );
    let client = MdeClient::new(tp).await;

    if args.actions.get {
        // Validate that --file is provided. This is a semantic requirement
        // (GetFile needs a path), not something clap can enforce via groups
        // because --file is shared across action types.
        let file_path = match &args.file {
            Some(path) => path.to_string_lossy().to_string(),
            None => {
                eprintln!("Error: --file is required when using -g (GetFile)");
                return ExitCode::FAILURE;
            }
        };

        let request = LiveResponseRequest {
            comment: "Live response via mde-lr CLI".to_string(),
            commands: vec![Command {
                command_type: CommandType::GetFile,
                params: vec![Param {
                    key: "Path".to_string(),
                    value: file_path,
                }],
            }],
        };

        match run_live_response(&client, &args.device_id, &request, None).await {
            Ok(results) => {
                for (i, data) in results.iter().enumerate() {
                    println!("Command {i} result: {} bytes", data.len());
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}
