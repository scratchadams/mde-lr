use serde::{Serialize, Deserialize};
use std::error::Error;

use crate::client::MdeClient;

#[derive(Debug, Serialize, Deserialize)]
pub struct LiveResponseRequest {
    #[serde(rename = "Commands")]
    pub commands: Vec<Command>,
    #[serde(rename = "Comment")]
    pub comment: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Command {
    #[serde(rename = "type")]
    pub command_type: CommandType,
    pub params: Vec<Param>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CommandType {
    RunScript,
    GetFile,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Param {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct MachineAction {
    pub id: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct DownloadLink {
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct ScriptResult {
    pub script_name: String,
    pub exit_code: i32,
    pub script_output: String,
    pub script_errors: String,
}

pub async fn run_live_response(
    client: &MdeClient,
    machine_id: &str,
    request: &LiveResponseRequest,
) -> Result<Vec<bytes::Bytes>, Box<dyn Error + Send + Sync>> {
    let path = format!("api/machines/{}/runliveresponse", machine_id);
    let action: MachineAction = client.post(&path, request).await?;

    let poll_path = format!("api/machineactions/{}", action.id);
    let completed = loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let status: MachineAction = client.get(&poll_path).await?;
        match status.status.as_str() {
            "Succeeded" => break status,
            "Failed" | "Cancelled" => {
                return Err(format!("Live response action {}: {}", status.status, status.id).into());
            }
            _ => continue,
        }
    };

    let mut results = Vec::new();
    for (i, _cmd) in request.commands.iter().enumerate() {
        let link_path = format!(
            "api/machineactions/{}/GetLiveResponseResultDownloadLink(index={})",
            completed.id, i
        );
        let link: DownloadLink = client.get(&link_path).await?;
        let data = client.download(&link.value).await?;
        results.push(data);
    }

    Ok(results)
}
