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
///
/// Currently only `-g` (GetFile) is implemented. Additional actions
/// (PutFile, RunScript) will be added as flags here when ready.
#[derive(clap::Args)]
#[group(required = true, multiple = false)]
struct ActionFlags {
    /// Collect a file from the remote device via Live Response GetFile.
    #[arg(short)]
    get: bool,
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
    let client = MdeClient::new(tp, None).await;

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Base arguments that satisfy all mandatory fields.
    /// Tests append or omit flags from this baseline.
    fn base_args() -> Vec<&'static str> {
        vec![
            "mde-lr",
            "--device-id",
            "dev-123",
            "--tenant-id",
            "tid-456",
            "--client-id",
            "cid-789",
            "--secret",
            "s3cret",
        ]
    }

    #[test]
    fn missing_action_flag_is_rejected() {
        // Clap's `group(required = true)` on ActionFlags should reject
        // a command line with no action flag. This prevents silent no-ops
        // where the CLI appears to succeed but does nothing.
        let args = base_args();
        let result = Cli::try_parse_from(args);
        assert!(
            result.is_err(),
            "parsing should fail when no action flag is provided"
        );
    }

    #[test]
    fn getfile_without_file_flag_parses_successfully() {
        // Clap treats --file as optional (it's `Option<PathBuf>`), so
        // parsing succeeds. The semantic check (--file required for -g)
        // happens at runtime in main(), not at parse time. This test
        // documents that separation of concerns.
        let mut args = base_args();
        args.push("-g");
        let cli = Cli::try_parse_from(args).expect("should parse with -g but no --file");
        assert!(cli.actions.get, "get flag should be set");
        assert!(
            cli.file.is_none(),
            "--file should be None when not provided"
        );
    }

    #[test]
    fn valid_getfile_args_parse_with_all_fields() {
        // Full valid invocation: all mandatory args + action flag + --file.
        // Verifies that clap populates every field correctly.
        let mut args = base_args();
        args.extend_from_slice(&["-g", "--file", "/tmp/evidence.zip"]);
        let cli = Cli::try_parse_from(args).expect("should parse a complete valid command");
        assert_eq!(cli.device_id, "dev-123");
        assert_eq!(cli.tenant_id, "tid-456");
        assert_eq!(cli.client_id, "cid-789");
        assert_eq!(cli.secret, "s3cret");
        assert!(cli.actions.get);
        assert_eq!(
            cli.file.as_ref().unwrap().to_str().unwrap(),
            "/tmp/evidence.zip"
        );
    }
}
