// src/ct_monitor.rs
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};
use log::{debug, error, info};
use prism_prover::Prover;
use prism_keys::SigningKey;
use std::sync::Arc;
use crate::prism_client;

#[derive(Debug, Deserialize, Serialize)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub timestamp: u64,
    pub sha256_root_hash: String, // Base64 encoded
    pub tree_head_signature: String, // Base64 encoded
}

pub async fn fetch_sth(log_url: &str) -> Result<SignedTreeHead> {
    let client = reqwest::Client::new();
    let url = format!("{}/ct/v1/get-sth", log_url);
    
    debug!("Fetching STH from: {}", url);
    
    let response = client.get(&url)
        .timeout(Duration::from_secs(30))
        .send()
        .await?;
        
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await?;
        error!("Failed to fetch STH. Status: {}, Body: {}", status, body);
        return Err(anyhow::anyhow!("Failed to fetch STH"));
    }
    
    let sth: SignedTreeHead = response.json().await?;
    Ok(sth)
}

pub async fn monitor_log(
    log_url: &str,
    log_id: &str,
    prover: Arc<Prover>,
    signing_key: SigningKey,
) -> Result<()> {
    info!("Starting monitoring for CT log: {}", log_id);
    
    let mut consecutive_failures = 0;
    
    loop {
        match fetch_sth(log_url).await {
            Ok(sth) => {
                info!("Fetched STH for {}: tree_size={}, timestamp={}", 
                    log_id, sth.tree_size, sth.timestamp);
                
                // Convert STH to bytes
                let sth_bytes = serde_json::to_vec(&sth)?;
                
                // Submit STH to the devnet
                match prism_client::submit_sth(log_id, &sth, Vec::new()).await {
                    Ok(_) => {
                        info!("Successfully submitted STH for {}", log_id);
                        consecutive_failures = 0;
                    },
                    Err(e) => {
                        error!("Error submitting STH for {}: {}", log_id, e);
                        consecutive_failures += 1;
                    }
                }
            }
            Err(e) => {
                error!("Error fetching STH from {}: {}", log_id, e);
                consecutive_failures += 1;
            }
        }
        
        let current_backoff = calculate_backoff(consecutive_failures);
        debug!("Waiting {} seconds before next fetch for {}", 
            current_backoff.as_secs(), log_id);
        sleep(current_backoff).await;
    }
}

fn calculate_backoff(failures: u32) -> Duration {
    let base = Duration::from_secs(300); // 5 minutes
    let max = Duration::from_secs(3600); // 1 hour
    let multiplier = (1.5_f64).powi(failures as i32);
    
    let backoff = base.mul_f64(multiplier);
    std::cmp::min(backoff, max)
}