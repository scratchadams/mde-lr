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
use mde_lr::live_response::{
    Command, CommandType, LiveResponseRequest, Param, ScriptResult, run_live_response,
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Remote file path (required for GetFile and PutFile commands).
    #[arg(long)]
    file: Option<std::path::PathBuf>,

    /// Script name to execute on the remote device (required for RunScript).
    /// The script must already exist in the MDE Live Response library.
    #[arg(long)]
    script: Option<String>,

    /// Arguments to pass to the script (optional, used with RunScript).
    /// Allows values starting with hyphens (e.g. "-Verbose") since
    /// PowerShell parameters commonly use that syntax.
    #[arg(long, allow_hyphen_values = true)]
    args: Option<String>,

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
    /// Collect a file from the remote device via Live Response GetFile.
    #[arg(short)]
    get: bool,

    /// Execute a PowerShell script on the remote device via Live Response RunScript.
    /// Requires --script (and optionally --args).
    #[arg(short)]
    run: bool,

    /// Upload a file from the MDE library to the remote device via Live Response PutFile.
    /// Requires --file.
    #[arg(short)]
    put: bool,
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

    // Build the LiveResponseRequest based on the selected action flag.
    // Each action has its own parameter validation: GetFile and PutFile
    // require --file, RunScript requires --script. These are semantic
    // requirements that clap can't enforce via groups because the flags
    // are shared across action types.
    let request = if args.actions.get {
        let file_path = match &args.file {
            Some(path) => path.to_string_lossy().to_string(),
            None => {
                eprintln!("Error: --file is required when using -g (GetFile)");
                return ExitCode::FAILURE;
            }
        };

        LiveResponseRequest {
            comment: "Live response via mde-lr CLI".to_string(),
            commands: vec![Command {
                command_type: CommandType::GetFile,
                params: vec![Param {
                    key: "Path".to_string(),
                    value: file_path,
                }],
            }],
        }
    } else if args.actions.run {
        let script_name = match &args.script {
            Some(name) => name.clone(),
            None => {
                eprintln!("Error: --script is required when using -r (RunScript)");
                return ExitCode::FAILURE;
            }
        };

        let mut params = vec![Param {
            key: "ScriptName".to_string(),
            value: script_name,
        }];

        // Script arguments are optional — many scripts run without parameters.
        if let Some(script_args) = &args.args {
            params.push(Param {
                key: "Args".to_string(),
                value: script_args.clone(),
            });
        }

        LiveResponseRequest {
            comment: "Live response via mde-lr CLI".to_string(),
            commands: vec![Command {
                command_type: CommandType::RunScript,
                params,
            }],
        }
    } else if args.actions.put {
        let file_path = match &args.file {
            Some(path) => path.to_string_lossy().to_string(),
            None => {
                eprintln!("Error: --file is required when using -p (PutFile)");
                return ExitCode::FAILURE;
            }
        };

        LiveResponseRequest {
            comment: "Live response via mde-lr CLI".to_string(),
            commands: vec![Command {
                command_type: CommandType::PutFile,
                params: vec![Param {
                    key: "Path".to_string(),
                    value: file_path,
                }],
            }],
        }
    } else {
        // This branch is unreachable because clap enforces exactly one
        // action flag via the group constraint, but we handle it explicitly
        // to avoid silently succeeding with no action.
        eprintln!("Error: no action flag provided");
        return ExitCode::FAILURE;
    };

    match run_live_response(&client, &args.device_id, &request, None).await {
        Ok(results) => {
            for (i, data) in results.iter().enumerate() {
                // For RunScript results, parse and display the structured output
                // (exit code, stdout, stderr) rather than just the byte count.
                // GetFile and PutFile results are opaque binary data where the
                // byte count is the most useful summary.
                if args.actions.run {
                    match serde_json::from_slice::<ScriptResult>(data) {
                        Ok(script_result) => {
                            println!(
                                "Command {i}: script '{}' exited with code {}",
                                script_result.script_name, script_result.exit_code
                            );
                            if !script_result.script_output.is_empty() {
                                println!("{}", script_result.script_output);
                            }
                            if !script_result.script_errors.is_empty() {
                                eprintln!("Script errors:\n{}", script_result.script_errors);
                            }
                        }
                        Err(e) => {
                            // Fall back to raw byte count if the result isn't valid
                            // ScriptResult JSON (shouldn't happen, but fail gracefully).
                            eprintln!("Warning: could not parse script result: {e}");
                            println!("Command {i} result: {} bytes", data.len());
                        }
                    }
                } else {
                    println!("Command {i} result: {} bytes", data.len());
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
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

    #[test]
    fn runscript_parses_with_script_and_args() {
        // Full RunScript invocation with --script and --args.
        // Verifies that clap populates the script name and arguments.
        let mut args = base_args();
        args.extend_from_slice(&["-r", "--script", "whoami.ps1", "--args", "-Verbose"]);
        let cli =
            Cli::try_parse_from(args).expect("should parse RunScript with --script and --args");
        assert!(cli.actions.run, "run flag should be set");
        assert_eq!(cli.script.as_deref(), Some("whoami.ps1"));
        assert_eq!(cli.args.as_deref(), Some("-Verbose"));
    }

    #[test]
    fn runscript_parses_without_args() {
        // RunScript with --script but no --args is valid — many scripts
        // run without parameters.
        let mut args = base_args();
        args.extend_from_slice(&["-r", "--script", "collector.ps1"]);
        let cli = Cli::try_parse_from(args).expect("should parse RunScript without --args");
        assert!(cli.actions.run);
        assert_eq!(cli.script.as_deref(), Some("collector.ps1"));
        assert!(
            cli.args.is_none(),
            "--args should be None when not provided"
        );
    }

    #[test]
    fn runscript_without_script_flag_parses_successfully() {
        // Clap treats --script as optional (it's `Option<String>`), so
        // parsing succeeds. The semantic check (--script required for -r)
        // happens at runtime in main(), not at parse time. Same pattern
        // as GetFile's --file requirement.
        let mut args = base_args();
        args.push("-r");
        let cli = Cli::try_parse_from(args).expect("should parse with -r but no --script");
        assert!(cli.actions.run, "run flag should be set");
        assert!(
            cli.script.is_none(),
            "--script should be None when not provided"
        );
    }

    #[test]
    fn putfile_parses_with_file() {
        // Full PutFile invocation with --file.
        let mut args = base_args();
        args.extend_from_slice(&["-p", "--file", "C:\\tools\\agent.exe"]);
        let cli = Cli::try_parse_from(args).expect("should parse PutFile with --file");
        assert!(cli.actions.put, "put flag should be set");
        assert_eq!(
            cli.file.as_ref().unwrap().to_str().unwrap(),
            "C:\\tools\\agent.exe"
        );
    }

    #[test]
    fn putfile_without_file_flag_parses_successfully() {
        // Same pattern as GetFile — --file is optional at parse time,
        // validated at runtime.
        let mut args = base_args();
        args.push("-p");
        let cli = Cli::try_parse_from(args).expect("should parse with -p but no --file");
        assert!(cli.actions.put, "put flag should be set");
        assert!(
            cli.file.is_none(),
            "--file should be None when not provided"
        );
    }

    #[test]
    fn conflicting_action_flags_are_rejected() {
        // Clap's `group(multiple = false)` should reject multiple action
        // flags. This prevents ambiguous invocations where the user passes
        // both -g and -r, for example.
        let mut args = base_args();
        args.extend_from_slice(&["-g", "-r"]);
        let result = Cli::try_parse_from(args);
        assert!(
            result.is_err(),
            "parsing should fail when multiple action flags are provided"
        );
    }
}
