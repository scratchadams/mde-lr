//! CLI entry point for mde-lr — a Microsoft Defender for Endpoint Live Response client.
//!
//! Authenticates via OAuth2 client credentials, then dispatches to the
//! appropriate MDE API action based on CLI flags (`-g` for GetFile, etc.).
//!
//! Exit codes:
//! - 0: success
//! - 1: runtime error (auth failure, API error, timeout, etc.)
//! - 2: argument validation error (clap handles this automatically)

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use mde_lr::alerts;
use mde_lr::auth::TokenProvider;
use mde_lr::client::MdeClient;
use mde_lr::library;
use mde_lr::live_response::{
    Command, CommandType, LiveResponseRequest, Param, ScriptResult, run_live_response,
};
use mde_lr::machine_actions;
use mde_lr::machines;

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

    /// Output file path for saving downloaded results to disk.
    /// Required for GetFile (otherwise the downloaded bytes are lost).
    /// For RunScript, the raw JSON result is written to this path in
    /// addition to the structured output printed to stdout.
    /// When multiple commands produce results, files are written with
    /// an index suffix (e.g. "output_0.zip", "output_1.zip").
    #[arg(long)]
    out: Option<std::path::PathBuf>,

    #[arg(long)]
    config: Option<std::path::PathBuf>,

    /// MDE device ID to target for live response actions.
    /// Required for -g, -r, -p but not for -t (token inspection).
    #[arg(long)]
    device_id: Option<String>,

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

    /// Audit comment attached to machine actions (isolate, scan, etc.).
    /// Defaults to "Action via mde-lr CLI" if not provided.
    #[arg(long)]
    comment: Option<String>,

    /// Isolation type: "Full", "Selective", or "UnManagedDevice".
    /// Only used with --isolate. Defaults to "Full".
    #[arg(long, default_value = "Full")]
    isolation_type: String,

    /// AV scan type: "Quick" or "Full".
    /// Only used with --scan. Defaults to "Quick".
    #[arg(long, default_value = "Quick")]
    scan_type: String,

    /// SHA-1 hash of a file to stop and quarantine.
    /// Required when using --stop-quarantine.
    #[arg(long)]
    sha1: Option<String>,

    /// OData $filter expression for --list-machines and --list-alerts.
    /// Example: "healthStatus eq 'Active'" or "severity eq 'High'"
    #[arg(long)]
    filter: Option<String>,

    /// Description for a library file upload (used with --upload-library).
    #[arg(long)]
    description: Option<String>,

    /// Alert ID for --get-alert and --update-alert.
    #[arg(long)]
    alert_id: Option<String>,

    /// Comma-separated alert IDs for --batch-update-alerts.
    #[arg(long)]
    alert_ids: Option<String>,

    /// Alert status: "New", "InProgress", or "Resolved".
    /// Used with --update-alert and --batch-update-alerts.
    #[arg(long)]
    status: Option<String>,

    /// Alert classification: "TruePositive", "InformationalExpectedActivity",
    /// or "FalsePositive". Used with --update-alert and --batch-update-alerts.
    #[arg(long)]
    classification: Option<String>,

    /// Alert determination (varies by classification).
    /// Used with --update-alert and --batch-update-alerts.
    #[arg(long)]
    determination: Option<String>,

    /// User or mailbox to assign an alert to (email address).
    /// Used with --update-alert and --batch-update-alerts.
    #[arg(long)]
    assigned_to: Option<String>,

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

    /// Acquire an OAuth2 token and print it to stdout for inspection.
    /// Does not require --device-id. Useful for debugging auth configuration,
    /// verifying credentials, and inspecting token claims via jwt.ms or jwt.io.
    #[arg(short)]
    token: bool,

    /// Isolate a device from the network. Use --isolation-type to control
    /// the isolation mode (defaults to "Full"). Requires --device-id.
    #[arg(long)]
    isolate: bool,

    /// Release a device from network isolation. Requires --device-id.
    #[arg(long)]
    unisolate: bool,

    /// Run a Microsoft Defender Antivirus scan on a device. Use --scan-type
    /// to choose "Quick" or "Full" (defaults to "Quick"). Requires --device-id.
    #[arg(long)]
    scan: bool,

    /// Collect a forensic investigation package from a device. Requires --device-id.
    #[arg(long)]
    collect_investigation: bool,

    /// Stop execution of a file and quarantine it on a device.
    /// Requires --device-id and --sha1. Requires --device-id.
    #[arg(long)]
    stop_quarantine: bool,

    /// Restrict application execution on a device (only Microsoft-signed apps allowed).
    /// Requires --device-id.
    #[arg(long)]
    restrict_execution: bool,

    /// Remove application execution restrictions from a device. Requires --device-id.
    #[arg(long)]
    unrestrict_execution: bool,

    /// Retrieve information about a single device by ID.
    /// Requires --device-id. Prints JSON to stdout.
    #[arg(long)]
    get_machine: bool,

    /// List devices visible to the tenant. Use --filter for OData filtering.
    /// Does not require --device-id. Prints JSON to stdout.
    #[arg(long)]
    list_machines: bool,

    /// List all files in the Live Response library.
    /// Does not require --device-id. Prints JSON to stdout.
    #[arg(long)]
    list_library: bool,

    /// Upload a file to the Live Response library.
    /// Requires --file (local path to the file to upload).
    /// Optionally use --description. Does not require --device-id.
    #[arg(long)]
    upload_library: bool,

    /// Delete a file from the Live Response library by name.
    /// Requires --file (the library filename, not a local path).
    /// Does not require --device-id.
    #[arg(long)]
    delete_library: bool,

    /// List security alerts visible to the tenant. Use --filter for OData filtering.
    /// Does not require --device-id. Prints JSON to stdout.
    #[arg(long)]
    list_alerts: bool,

    /// Retrieve a single alert by ID. Requires --alert-id.
    /// Does not require --device-id. Prints JSON to stdout.
    #[arg(long)]
    get_alert: bool,

    /// Update an alert's status, classification, or assignment.
    /// Requires --alert-id. Use --status, --classification, --determination,
    /// --assigned-to, and/or --comment. Does not require --device-id.
    #[arg(long)]
    update_alert: bool,

    /// Batch-update multiple alerts. Requires --alert-ids (comma-separated).
    /// Use --status, --classification, --determination, --assigned-to,
    /// and/or --comment. Does not require --device-id.
    /// Rate limit: 10 calls/min (stricter than standard 100/min).
    #[arg(long)]
    batch_update_alerts: bool,
}

/// Computes the output file path for a given command index.
///
/// When the request contains a single command, the path is used as-is
/// (e.g. `--out results.zip` → `results.zip`). When there are multiple
/// commands, an index suffix is inserted before the file extension to
/// disambiguate results (e.g. `results.zip` → `results_0.zip`,
/// `results_1.zip`). This prevents later commands from silently
/// overwriting earlier results.
fn output_path_for_index(base: &std::path::Path, index: usize, total: usize) -> PathBuf {
    if total <= 1 {
        return base.to_path_buf();
    }
    // Insert "_N" before the extension: "foo.zip" → "foo_0.zip"
    // If there's no extension: "foo" → "foo_0"
    let stem = base.file_stem().unwrap_or_default().to_string_lossy();
    let ext = base.extension().map(|e| e.to_string_lossy());
    let indexed_name = match ext {
        Some(ext) => format!("{stem}_{index}.{ext}"),
        None => format!("{stem}_{index}"),
    };
    base.with_file_name(indexed_name)
}

/// Prints a machine action result to stdout and returns the appropriate exit code.
///
/// Machine action endpoints (isolate, scan, etc.) fire-and-forget by default
/// (no polling in the CLI). The user sees the action ID and status so they
/// can track it in the MDE portal or poll separately.
fn run_machine_action(
    result: Result<mde_lr::action::MachineAction, mde_lr::error::MdeError>,
) -> ExitCode {
    match result {
        Ok(action) => {
            println!("Action submitted successfully");
            println!("  Action ID: {}", action.id);
            println!("  Status:    {:?}", action.status);
            if let Some(t) = &action.action_type {
                println!("  Type:      {t}");
            }
            if let Some(m) = &action.machine_id {
                println!("  Machine:   {m}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Cli::parse();

    // Token inspection mode: acquire a token and print it, then exit.
    // This path doesn't need --device-id or an MdeClient — it only
    // talks to Azure AD to verify that credentials are valid and to
    // let the operator inspect the token (e.g. paste into jwt.ms to
    // check claims, scopes, and expiry).
    if args.actions.token {
        let mut tp = TokenProvider::new(
            &args.tenant_id,
            &args.client_id,
            &args.secret,
            "https://api.securitycenter.microsoft.com/.default",
        );
        match tp.refresh_token().await {
            Ok(()) => match tp.token() {
                Some(token) => {
                    println!("{token}");
                    return ExitCode::SUCCESS;
                }
                None => {
                    eprintln!("Error: token missing after successful refresh");
                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // Create the authenticated client for all non-token actions.
    let tp = TokenProvider::new(
        &args.tenant_id,
        &args.client_id,
        &args.secret,
        "https://api.securitycenter.microsoft.com/.default",
    );
    let client = MdeClient::new(tp, None).await;

    // ── List machines (no --device-id required) ────────────────────────
    if args.actions.list_machines {
        match machines::list_machines(&client, args.filter.as_deref()).await {
            Ok(devices) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&devices).unwrap_or_else(|_| "[]".to_string())
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // ── List library files (no --device-id required) ─────────────────────
    if args.actions.list_library {
        match library::list_library_files(&client).await {
            Ok(files) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&files).unwrap_or_else(|_| "[]".to_string())
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // ── Upload library file (no --device-id required) ──────────────────
    if args.actions.upload_library {
        let file_path = match &args.file {
            Some(path) => path,
            None => {
                eprintln!("Error: --file is required when using --upload-library");
                return ExitCode::FAILURE;
            }
        };
        let file_bytes = match std::fs::read(file_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("Error: failed to read {}: {e}", file_path.display());
                return ExitCode::FAILURE;
            }
        };
        let file_name = file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        match library::upload_library_file(
            &client,
            &file_name,
            file_bytes,
            args.description.as_deref(),
            false,
        )
        .await
        {
            Ok(lib_file) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&lib_file).unwrap_or_else(|_| "{}".to_string())
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // ── Delete library file (no --device-id required) ──────────────────
    if args.actions.delete_library {
        let file_name = match &args.file {
            Some(path) => path.to_string_lossy().to_string(),
            None => {
                eprintln!(
                    "Error: --file is required when using --delete-library (library file name)"
                );
                return ExitCode::FAILURE;
            }
        };
        match library::delete_library_file(&client, &file_name).await {
            Ok(()) => {
                println!("Deleted library file: {file_name}");
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // ── List alerts (no --device-id required) ──────────────────────────
    if args.actions.list_alerts {
        match alerts::list_alerts(&client, args.filter.as_deref()).await {
            Ok(alert_list) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&alert_list).unwrap_or_else(|_| "[]".to_string())
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // ── Get alert (no --device-id required) ────────────────────────────
    if args.actions.get_alert {
        let alert_id = match &args.alert_id {
            Some(id) => id.as_str(),
            None => {
                eprintln!("Error: --alert-id is required for --get-alert");
                return ExitCode::FAILURE;
            }
        };
        match alerts::get_alert(&client, alert_id).await {
            Ok(alert) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&alert).unwrap_or_else(|_| "{}".to_string())
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // ── Update alert (no --device-id required) ─────────────────────────
    if args.actions.update_alert {
        let alert_id = match &args.alert_id {
            Some(id) => id.as_str(),
            None => {
                eprintln!("Error: --alert-id is required for --update-alert");
                return ExitCode::FAILURE;
            }
        };
        let update_req = alerts::UpdateAlertRequest {
            status: args.status.clone(),
            assigned_to: args.assigned_to.clone(),
            classification: args.classification.clone(),
            determination: args.determination.clone(),
            comment: args.comment.clone(),
        };
        match alerts::update_alert(&client, alert_id, &update_req).await {
            Ok(alert) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&alert).unwrap_or_else(|_| "{}".to_string())
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // ── Batch update alerts (no --device-id required) ──────────────────
    if args.actions.batch_update_alerts {
        let alert_ids: Vec<String> = match &args.alert_ids {
            Some(ids) => ids.split(',').map(|s| s.trim().to_string()).collect(),
            None => {
                eprintln!(
                    "Error: --alert-ids is required for --batch-update-alerts (comma-separated)"
                );
                return ExitCode::FAILURE;
            }
        };
        let batch_req = alerts::BatchUpdateAlertsRequest {
            alert_ids,
            status: args.status.clone(),
            assigned_to: args.assigned_to.clone(),
            classification: args.classification.clone(),
            determination: args.determination.clone(),
            comment: args.comment.clone(),
        };
        match alerts::batch_update_alerts(&client, &batch_req).await {
            Ok(()) => {
                println!("Batch update completed successfully");
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // All remaining actions require --device-id to target a specific machine.
    let device_id = match &args.device_id {
        Some(id) => id.as_str(),
        None => {
            eprintln!("Error: --device-id is required for this action");
            return ExitCode::FAILURE;
        }
    };

    // ── Get machine info ───────────────────────────────────────────────
    if args.actions.get_machine {
        match machines::get_machine(&client, device_id).await {
            Ok(machine) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&machine).unwrap_or_else(|_| "{}".to_string())
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // ── Machine actions (isolate, scan, quarantine, etc.) ──────────────
    let comment = args
        .comment
        .clone()
        .unwrap_or_else(|| "Action via mde-lr CLI".to_string());

    if args.actions.isolate {
        let req = machine_actions::IsolateRequest {
            comment,
            isolation_type: args.isolation_type.clone(),
        };
        return run_machine_action(
            machine_actions::isolate_machine(&client, device_id, &req, None).await,
        );
    }
    if args.actions.unisolate {
        let req = machine_actions::UnisolateRequest { comment };
        return run_machine_action(
            machine_actions::unisolate_machine(&client, device_id, &req, None).await,
        );
    }
    if args.actions.scan {
        let req = machine_actions::AntivirusScanRequest {
            comment,
            scan_type: args.scan_type.clone(),
        };
        return run_machine_action(
            machine_actions::run_antivirus_scan(&client, device_id, &req, None).await,
        );
    }
    if args.actions.collect_investigation {
        let req = machine_actions::CollectInvestigationPackageRequest { comment };
        return run_machine_action(
            machine_actions::collect_investigation_package(&client, device_id, &req, None).await,
        );
    }
    if args.actions.stop_quarantine {
        let sha1 = match &args.sha1 {
            Some(s) => s.clone(),
            None => {
                eprintln!("Error: --sha1 is required when using --stop-quarantine");
                return ExitCode::FAILURE;
            }
        };
        let req = machine_actions::StopAndQuarantineFileRequest { comment, sha1 };
        return run_machine_action(
            machine_actions::stop_and_quarantine_file(&client, device_id, &req, None).await,
        );
    }
    if args.actions.restrict_execution {
        let req = machine_actions::RestrictCodeExecutionRequest { comment };
        return run_machine_action(
            machine_actions::restrict_code_execution(&client, device_id, &req, None).await,
        );
    }
    if args.actions.unrestrict_execution {
        let req = machine_actions::UnrestrictCodeExecutionRequest { comment };
        return run_machine_action(
            machine_actions::unrestrict_code_execution(&client, device_id, &req, None).await,
        );
    }

    println!("DeviceID: {device_id}");

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

    match run_live_response(&client, device_id, &request, None).await {
        Ok(results) => {
            for (i, data) in results.iter().enumerate() {
                // Write result bytes to disk when --out is provided.
                // For a single command, the file is written to the exact --out path.
                // For multiple commands, an index suffix is inserted before the
                // extension (e.g. "output.zip" → "output_0.zip", "output_1.zip")
                // to avoid overwriting results.
                if let Some(out_path) = &args.out {
                    let dest = output_path_for_index(out_path, i, results.len());
                    match std::fs::write(&dest, data) {
                        Ok(()) => {
                            println!(
                                "Command {i}: wrote {} bytes to {}",
                                data.len(),
                                dest.display()
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "Error: failed to write {} bytes to {}: {e}",
                                data.len(),
                                dest.display()
                            );
                            return ExitCode::FAILURE;
                        }
                    }
                }

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
                } else if args.out.is_none() {
                    // Only print the byte count summary when --out is not provided,
                    // since the write confirmation already includes the byte count.
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
        assert_eq!(cli.device_id.as_deref(), Some("dev-123"));
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

    #[test]
    fn token_flag_parses_without_device_id() {
        // Token inspection (-t) doesn't target a device, so --device-id
        // should not be required. This lets operators verify their Azure AD
        // credentials without needing to know a device ID.
        let args = vec![
            "mde-lr",
            "--tenant-id",
            "tid-456",
            "--client-id",
            "cid-789",
            "--secret",
            "s3cret",
            "-t",
        ];
        let cli = Cli::try_parse_from(args).expect("should parse -t without --device-id");
        assert!(cli.actions.token, "token flag should be set");
        assert!(
            cli.device_id.is_none(),
            "--device-id should be None when not provided"
        );
    }

    #[test]
    fn token_flag_conflicts_with_action_flags() {
        // -t is mutually exclusive with -g, -r, -p because it's in the
        // same action group. You either inspect a token or run a live
        // response action, not both.
        let mut args = base_args();
        args.extend_from_slice(&["-t", "-g"]);
        let result = Cli::try_parse_from(args);
        assert!(
            result.is_err(),
            "parsing should fail when -t is combined with another action flag"
        );
    }

    // ── --out flag tests ─────────────────────────────────────────────

    #[test]
    fn getfile_parses_with_out_flag() {
        // GetFile with --out specifies where to write the downloaded bytes.
        // This is the primary use case for --out — without it, GetFile
        // downloads bytes but has nowhere to save them.
        let mut args = base_args();
        args.extend_from_slice(&[
            "-g",
            "--file",
            "/tmp/evidence.zip",
            "--out",
            "/tmp/local.zip",
        ]);
        let cli = Cli::try_parse_from(args).expect("should parse -g with --out");
        assert!(cli.actions.get);
        assert_eq!(
            cli.out.as_ref().unwrap().to_str().unwrap(),
            "/tmp/local.zip"
        );
    }

    #[test]
    fn runscript_parses_with_out_flag() {
        // RunScript with --out saves the raw JSON result to disk in
        // addition to printing structured output to stdout.
        let mut args = base_args();
        args.extend_from_slice(&[
            "-r",
            "--script",
            "collector.ps1",
            "--out",
            "/tmp/result.json",
        ]);
        let cli = Cli::try_parse_from(args).expect("should parse -r with --out");
        assert!(cli.actions.run);
        assert_eq!(
            cli.out.as_ref().unwrap().to_str().unwrap(),
            "/tmp/result.json"
        );
    }

    #[test]
    fn out_flag_defaults_to_none() {
        // --out is optional. When omitted, results are printed to stdout
        // (byte count for GetFile/PutFile, structured output for RunScript).
        let mut args = base_args();
        args.extend_from_slice(&["-g", "--file", "/tmp/evidence.zip"]);
        let cli = Cli::try_parse_from(args).expect("should parse without --out");
        assert!(cli.out.is_none(), "--out should be None when not provided");
    }

    // ── output_path_for_index tests ──────────────────────────────────

    #[test]
    fn output_path_single_command_returns_base_unchanged() {
        // When there's only one command, no index suffix is needed —
        // the user's --out path is used exactly as given.
        let base = PathBuf::from("/tmp/result.zip");
        let result = output_path_for_index(&base, 0, 1);
        assert_eq!(result, PathBuf::from("/tmp/result.zip"));
    }

    #[test]
    fn output_path_multiple_commands_inserts_index_before_extension() {
        // When multiple commands produce results, an index is inserted
        // before the extension to prevent overwriting. This matches the
        // common convention used by tools like wget and curl.
        let base = PathBuf::from("/tmp/result.zip");
        assert_eq!(
            output_path_for_index(&base, 0, 3),
            PathBuf::from("/tmp/result_0.zip")
        );
        assert_eq!(
            output_path_for_index(&base, 2, 3),
            PathBuf::from("/tmp/result_2.zip")
        );
    }

    #[test]
    fn output_path_no_extension_appends_index() {
        // Files without extensions get the index appended directly.
        let base = PathBuf::from("/tmp/output");
        assert_eq!(
            output_path_for_index(&base, 1, 2),
            PathBuf::from("/tmp/output_1")
        );
    }

    // ── Machine action flags ────────────────────────────────────────

    #[test]
    fn isolate_flag_parses_with_defaults() {
        let mut args = base_args();
        args.push("--isolate");
        let cli = Cli::try_parse_from(args).expect("should parse --isolate");
        assert!(cli.actions.isolate);
        // Default isolation type is "Full".
        assert_eq!(cli.isolation_type, "Full");
        // Default comment is None (main() provides a default string).
        assert!(cli.comment.is_none());
    }

    #[test]
    fn isolate_flag_with_selective_type_and_comment() {
        let mut args = base_args();
        args.extend_from_slice(&[
            "--isolate",
            "--isolation-type",
            "Selective",
            "--comment",
            "Isolate for investigation",
        ]);
        let cli = Cli::try_parse_from(args).expect("should parse --isolate with options");
        assert!(cli.actions.isolate);
        assert_eq!(cli.isolation_type, "Selective");
        assert_eq!(cli.comment.as_deref(), Some("Isolate for investigation"));
    }

    #[test]
    fn scan_flag_parses_with_full_scan_type() {
        let mut args = base_args();
        args.extend_from_slice(&["--scan", "--scan-type", "Full"]);
        let cli = Cli::try_parse_from(args).expect("should parse --scan with --scan-type");
        assert!(cli.actions.scan);
        assert_eq!(cli.scan_type, "Full");
    }

    #[test]
    fn stop_quarantine_parses_with_sha1() {
        let mut args = base_args();
        args.extend_from_slice(&[
            "--stop-quarantine",
            "--sha1",
            "87662bc3d60e4200ceaf7aae249d1c343f4b83c9",
        ]);
        let cli = Cli::try_parse_from(args).expect("should parse --stop-quarantine with --sha1");
        assert!(cli.actions.stop_quarantine);
        assert_eq!(
            cli.sha1.as_deref(),
            Some("87662bc3d60e4200ceaf7aae249d1c343f4b83c9")
        );
    }

    #[test]
    fn get_machine_flag_parses() {
        let mut args = base_args();
        args.push("--get-machine");
        let cli = Cli::try_parse_from(args).expect("should parse --get-machine");
        assert!(cli.actions.get_machine);
    }

    #[test]
    fn list_machines_flag_parses_without_device_id() {
        // --list-machines doesn't require --device-id.
        let args = vec![
            "mde-lr",
            "--tenant-id",
            "tid-456",
            "--client-id",
            "cid-789",
            "--secret",
            "s3cret",
            "--list-machines",
        ];
        let cli = Cli::try_parse_from(args).expect("should parse --list-machines");
        assert!(cli.actions.list_machines);
        assert!(cli.device_id.is_none());
    }

    #[test]
    fn list_machines_with_filter() {
        let args = vec![
            "mde-lr",
            "--tenant-id",
            "tid-456",
            "--client-id",
            "cid-789",
            "--secret",
            "s3cret",
            "--list-machines",
            "--filter",
            "healthStatus eq 'Active'",
        ];
        let cli = Cli::try_parse_from(args).expect("should parse --list-machines with --filter");
        assert!(cli.actions.list_machines);
        assert_eq!(cli.filter.as_deref(), Some("healthStatus eq 'Active'"));
    }

    #[test]
    fn isolate_conflicts_with_scan() {
        // Machine action flags are mutually exclusive (same group as -g, -r, -p).
        let mut args = base_args();
        args.extend_from_slice(&["--isolate", "--scan"]);
        let result = Cli::try_parse_from(args);
        assert!(
            result.is_err(),
            "parsing should fail when --isolate and --scan are both set"
        );
    }

    #[test]
    fn isolate_conflicts_with_getfile() {
        // Machine action flags conflict with live response flags too.
        let mut args = base_args();
        args.extend_from_slice(&["--isolate", "-g"]);
        let result = Cli::try_parse_from(args);
        assert!(
            result.is_err(),
            "parsing should fail when --isolate and -g are both set"
        );
    }

    // ── Library flags ──────────────────────────────────────────────────

    #[test]
    fn list_library_parses_without_device_id() {
        let args = vec![
            "mde-lr",
            "--tenant-id",
            "tid-456",
            "--client-id",
            "cid-789",
            "--secret",
            "s3cret",
            "--list-library",
        ];
        let cli = Cli::try_parse_from(args).expect("should parse --list-library");
        assert!(cli.actions.list_library);
        assert!(cli.device_id.is_none());
    }

    #[test]
    fn upload_library_parses_with_file_and_description() {
        let args = vec![
            "mde-lr",
            "--tenant-id",
            "tid-456",
            "--client-id",
            "cid-789",
            "--secret",
            "s3cret",
            "--upload-library",
            "--file",
            "/tmp/script.ps1",
            "--description",
            "Forensic collector",
        ];
        let cli = Cli::try_parse_from(args).expect("should parse --upload-library");
        assert!(cli.actions.upload_library);
        assert_eq!(
            cli.file.as_ref().unwrap().to_str().unwrap(),
            "/tmp/script.ps1"
        );
        assert_eq!(cli.description.as_deref(), Some("Forensic collector"));
    }

    #[test]
    fn delete_library_parses_with_file() {
        let args = vec![
            "mde-lr",
            "--tenant-id",
            "tid-456",
            "--client-id",
            "cid-789",
            "--secret",
            "s3cret",
            "--delete-library",
            "--file",
            "old-script.ps1",
        ];
        let cli = Cli::try_parse_from(args).expect("should parse --delete-library");
        assert!(cli.actions.delete_library);
    }

    // ── Alert flags ────────────────────────────────────────────────────

    #[test]
    fn list_alerts_parses_without_device_id() {
        let args = vec![
            "mde-lr",
            "--tenant-id",
            "tid-456",
            "--client-id",
            "cid-789",
            "--secret",
            "s3cret",
            "--list-alerts",
        ];
        let cli = Cli::try_parse_from(args).expect("should parse --list-alerts");
        assert!(cli.actions.list_alerts);
    }

    #[test]
    fn list_alerts_with_filter() {
        let args = vec![
            "mde-lr",
            "--tenant-id",
            "tid-456",
            "--client-id",
            "cid-789",
            "--secret",
            "s3cret",
            "--list-alerts",
            "--filter",
            "severity eq 'High'",
        ];
        let cli = Cli::try_parse_from(args).expect("should parse --list-alerts with --filter");
        assert!(cli.actions.list_alerts);
        assert_eq!(cli.filter.as_deref(), Some("severity eq 'High'"));
    }

    #[test]
    fn get_alert_parses_with_alert_id() {
        let args = vec![
            "mde-lr",
            "--tenant-id",
            "tid-456",
            "--client-id",
            "cid-789",
            "--secret",
            "s3cret",
            "--get-alert",
            "--alert-id",
            "alert-123",
        ];
        let cli = Cli::try_parse_from(args).expect("should parse --get-alert");
        assert!(cli.actions.get_alert);
        assert_eq!(cli.alert_id.as_deref(), Some("alert-123"));
    }

    #[test]
    fn update_alert_parses_with_all_fields() {
        let args = vec![
            "mde-lr",
            "--tenant-id",
            "tid-456",
            "--client-id",
            "cid-789",
            "--secret",
            "s3cret",
            "--update-alert",
            "--alert-id",
            "alert-456",
            "--status",
            "Resolved",
            "--classification",
            "FalsePositive",
            "--determination",
            "NotMalicious",
            "--assigned-to",
            "analyst@contoso.com",
            "--comment",
            "False positive confirmed",
        ];
        let cli = Cli::try_parse_from(args).expect("should parse --update-alert with all fields");
        assert!(cli.actions.update_alert);
        assert_eq!(cli.alert_id.as_deref(), Some("alert-456"));
        assert_eq!(cli.status.as_deref(), Some("Resolved"));
        assert_eq!(cli.classification.as_deref(), Some("FalsePositive"));
        assert_eq!(cli.determination.as_deref(), Some("NotMalicious"));
        assert_eq!(cli.assigned_to.as_deref(), Some("analyst@contoso.com"));
        assert_eq!(cli.comment.as_deref(), Some("False positive confirmed"));
    }

    #[test]
    fn batch_update_alerts_parses_with_ids() {
        let args = vec![
            "mde-lr",
            "--tenant-id",
            "tid-456",
            "--client-id",
            "cid-789",
            "--secret",
            "s3cret",
            "--batch-update-alerts",
            "--alert-ids",
            "alert-1,alert-2,alert-3",
            "--status",
            "Resolved",
        ];
        let cli = Cli::try_parse_from(args).expect("should parse --batch-update-alerts");
        assert!(cli.actions.batch_update_alerts);
        assert_eq!(cli.alert_ids.as_deref(), Some("alert-1,alert-2,alert-3"));
        assert_eq!(cli.status.as_deref(), Some("Resolved"));
    }

    #[test]
    fn list_alerts_conflicts_with_list_machines() {
        let args = vec![
            "mde-lr",
            "--tenant-id",
            "tid-456",
            "--client-id",
            "cid-789",
            "--secret",
            "s3cret",
            "--list-alerts",
            "--list-machines",
        ];
        let result = Cli::try_parse_from(args);
        assert!(
            result.is_err(),
            "parsing should fail when --list-alerts and --list-machines are both set"
        );
    }
}
