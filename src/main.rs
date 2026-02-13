//! CLI entry point for mde-lr — a Microsoft Defender for Endpoint Live Response client.
//!
//! Authenticates via OAuth2 client credentials, then dispatches to the
//! appropriate MDE API action based on CLI flags (`-g` for GetFile, etc.).

use clap::Parser;

use mde_lr::auth::TokenProvider;
use mde_lr::client::MdeClient;
use mde_lr::live_response::{
    run_live_response, CommandType, Command, LiveResponseRequest, Param,
};

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

    /// Azure AD client secret.
    #[arg(long)]
    secret: String,

    #[arg(long)]
    query: Option<bool>,

    #[command(flatten)]
    actions: ActionFlags,
}

/// Mutually-selectable action flags. Exactly one should be set per invocation.
#[derive(clap::Args)]
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
async fn main() {
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
        let request = LiveResponseRequest {
            comment: "Live response via mde-lr CLI".to_string(),
            commands: vec![Command {
                command_type: CommandType::GetFile,
                params: vec![Param {
                    key: "Path".to_string(),
                    value: args.file.as_ref().expect("--file required for GetFile").to_string_lossy().to_string(),
                }],
            }],
        };

        match run_live_response(&client, &args.device_id, &request).await {
            Ok(results) => {
                for (i, data) in results.iter().enumerate() {
                    println!("Command {} result: {} bytes", i, data.len());
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}
