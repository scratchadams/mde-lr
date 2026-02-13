use clap::Parser;

use crate::auth::TokenProvider;
use crate::client::MdeClient;
use crate::live_response::{
    run_live_response, CommandType, Command, LiveResponseRequest, Param,
};

mod auth;
mod live_response;
mod client;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    file: Option<std::path::PathBuf>,

    #[arg(long)]
    config: Option<std::path::PathBuf>,

    #[arg(long)]
    device_id: String,

    #[arg(long)]
    tenant_id: String,

    #[arg(long)]
    client_id: String,

    #[arg(long)]
    secret: String,

    #[arg(long)]
    query: Option<bool>,

    #[command(flatten)]
    actions: ActionFlags,
}

#[derive(clap::Args)]
struct ActionFlags {
    #[arg(short)]
    put: bool,

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
