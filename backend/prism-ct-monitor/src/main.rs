// src/main.rs
mod ct_monitor;
mod prism_client;
mod operations;

use std::sync::Arc;
use anyhow::{Result, anyhow};
use log::debug;
use prism_prover::Prover;
use keystore_rs::{KeyChain, KeyStore};
use prism_keys::SigningKey;
use futures::future::join_all;
use tokio::spawn;
use prism_da::{memory::InMemoryDataAvailabilityLayer, DataAvailabilityLayer};
use prism_storage::inmemory::InMemoryDatabase;
use prism_prover::{webserver::WebServerConfig, Config};

// Define service ID for Firefox CT monitoring
pub static SERVICE_ID: &str = "firefox_ct_monitor_service";

// Define the CT logs structure
pub struct CTLogInfo {
    id: &'static str,
    url: &'static str,
}

// Define Firefox-relevant CT logs
pub static FIREFOX_CT_LOGS: &[CTLogInfo] = &[
    CTLogInfo {
        id: "Argon2025h1",
        url: "https://ct.googleapis.com/logs/us1/argon2025h1/",
    },
    CTLogInfo {
        id: "Argon2025h2",
        url: "https://ct.googleapis.com/logs/us1/argon2025h2/",
    },
    CTLogInfo {
        id: "Argon2026h1",
        url: "https://ct.googleapis.com/logs/us1/argon2026h1/",
    },
    CTLogInfo {
        id: "Argon2026h2",
        url: "https://ct.googleapis.com/logs/us1/argon2026h2/",
    },
    CTLogInfo {
        id: "Xenon2025h1",
        url: "https://ct.googleapis.com/logs/us1/Xenon2025h1/",
    },
    CTLogInfo {
        id: "Xenon2025h2",
        url: "https://ct.googleapis.com/logs/us1/Xenon2025h2/",
    },
    CTLogInfo {
        id: "Xenon2026h1",
        url: "https://ct.googleapis.com/logs/us1/Xenon2026h1/",
    },
    CTLogInfo {
        id: "Xenon2026h2",
        url: "https://ct.googleapis.com/logs/us1/Xenon2026h2/",
    },

    CTLogInfo {
        id: "Nimbus2024",
        url: "https://ct.cloudflare.com/logs/nimbus2024",
    },
    CTLogInfo {
        id: "Nimbus2025",
        url: "https://ct.cloudflare.com/logs/nimbus2025/",
    },
    CTLogInfo {
        id: "Nimbus2026",
        url: "https://ct.cloudflare.com/logs/nimbus2026/",
    },
];

async fn get_prover_connection() -> Result<Arc<Prover>> {
    let db = InMemoryDatabase::new();
    let (da_layer, _, _) = InMemoryDataAvailabilityLayer::new(5);

    let keystore_sk = KeyChain
        .get_or_create_signing_key(SERVICE_ID)
        .map_err(|e| anyhow!("Error getting key from store: {}", e))?;

    let sk = SigningKey::Ed25519(Box::new(keystore_sk));

    let cfg = Config {
        prover: true,
        batcher: true,
        webserver: WebServerConfig {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 50524,
        },
        signing_key: sk.clone(),
        verifying_key: sk.verifying_key(),
        start_height: 1,
    };

    Ok(Arc::new(
        Prover::new(
            Arc::new(Box::new(db)),
            Arc::new(da_layer) as Arc<dyn DataAvailabilityLayer>,
            &cfg,
        )
        .unwrap(),
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Set up logging
    std::env::set_var("RUST_LOG", "debug");
    pretty_env_logger::init();

    debug!("Starting Firefox CT Monitor Service");

    // Get or create the service's signing key
    let keystore_sk = KeyChain
        .get_or_create_signing_key(SERVICE_ID)
        .map_err(|e| anyhow!("Error getting key from store: {}", e))?;
    
    let service_sk = SigningKey::Ed25519(Box::new(keystore_sk));

    // Connect to the running devnet
    let prover = get_prover_connection().await?;

    // Register our service if not already registered
    operations::register_service(prover.clone(), service_sk.clone()).await?;

    // Create accounts for all monitored CT logs
    for log in FIREFOX_CT_LOGS {
        operations::create_account(
            log.id.to_string(),
            prover.clone(),
            service_sk.clone()
        ).await?;
    }

    // Start monitoring all logs concurrently
    let monitor_handles = FIREFOX_CT_LOGS.iter().map(|log| {
        let prover = prover.clone();
        let service_sk = service_sk.clone();
        
        spawn(async move {
            if let Err(e) = ct_monitor::monitor_log(
                log.url,
                log.id,
                prover,
                service_sk
            ).await {
                eprintln!("Error monitoring {}: {}", log.id, e);
            }
        })
    }).collect::<Vec<_>>();

    // Wait for all monitoring tasks
    let results = join_all(monitor_handles).await;
    for result in results {
        if let Err(e) = result {
            eprintln!("Task error: {}", e);
        }
    }

    Ok(())
}