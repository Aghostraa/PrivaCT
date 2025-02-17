// prism-ct-monitor/src/prism_client.rs
use anyhow::Result;
use serde_json::json;
use log::debug;
use crate::ct_monitor::SignedTreeHead;

pub async fn submit_sth(log_id: &str, sth: &SignedTreeHead, proof: Vec<String>) -> Result<()> {
    let client = reqwest::Client::new();
    
    let payload = json!({
        "log_id": log_id,
        "tree_size": sth.tree_size,
        "timestamp": sth.timestamp,
        "root_hash": sth.sha256_root_hash,
        "signature": sth.tree_head_signature,
        "merkle_proof": proof,
    });

    debug!("Submitting STH for {} to Prism", log_id);
    
    // Update the URL to point to your devnet's endpoint
    client.post("http://127.0.0.1:50524/v1/submit_sth")
        .json(&payload)
        .send()
        .await?
        .error_for_status()?;

    debug!("Successfully submitted STH to Prism for {}", log_id);
    Ok(())
}