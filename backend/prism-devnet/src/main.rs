mod operations;

use anyhow::{anyhow, Result};
use keystore_rs::{KeyChain, KeyStore};
use log::{error, debug};
use prism_da::{memory::InMemoryDataAvailabilityLayer, DataAvailabilityLayer};
use prism_keys::SigningKey;
use prism_storage::inmemory::InMemoryDatabase;
use std::sync::Arc;
use tokio::{spawn, time::{sleep, Duration}};
use warp::Filter;
use warp::reply::WithStatus;
use warp::reply::Json;
use prism_prover::{webserver::WebServerConfig, Config, Prover};
use prism_common::digest::Digest;  // Added Digest
use prism_common::operation::SignatureBundle;  // Added SignatureBundle

pub static SERVICE_ID: &str = "test_service";

#[derive(serde::Deserialize, serde::Serialize, Debug)]
struct STHPayload {
    log_id: String,
    tree_size: u64,
    timestamp: u64,
    sha256_root_hash: String,     // Change from root_hash to match CTClient
    tree_head_signature: String,   // Change from signature to match CTClient
    merkle_proof: Vec<String>,
}

#[derive(Debug)]
struct CustomRejection(String);

impl warp::reject::Reject for CustomRejection {}

// Add this helper function
fn with_prover(prover: Arc<Prover>) -> impl Filter<Extract = (Arc<Prover>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || prover.clone())
}

// Wait for the account to become available
async fn wait_for_account(user_id: &String, prover: Arc<Prover>) -> Result<()> {
    let mut retries = 0;
    while retries < 10 {
        if let prism_tree::AccountResponse::Found(_, _) = prover.get_account(user_id).await? {
            debug!("Account {} is now available.", user_id);
            return Ok(());
        }
        debug!("Waiting for account {} to be available...", user_id);
        sleep(Duration::from_secs(2)).await;
        retries += 1;
    }
    Err(anyhow!("Account {} not available after waiting", user_id))
}

async fn handle_sth_submission(
    payload: STHPayload,
    prover: Arc<Prover>
) -> Result<impl warp::Reply, warp::Rejection> {
    debug!("Received STH submission with payload: {:?}", payload);

    // First, register the service if it's not already registered
    debug!("Ensuring service is registered");
    operations::register_service(prover.clone())
        .await
        .map_err(|e| {
            error!("Failed to register service: {}", e);
            warp::reject::custom(CustomRejection(e.to_string()))
        })?;

    // Let's wait a moment to ensure the service registration is processed
    sleep(Duration::from_secs(2)).await;

    // Now proceed with account creation and data submission
    debug!("Creating/checking account for log_id: {}", payload.log_id);
    let _account = operations::create_account(
        payload.log_id.clone(),
        prover.clone(),
    ).await.map_err(|e| {
        error!("Failed to create account: {}", e);
        warp::reject::custom(CustomRejection(e.to_string()))
    })?;

    // Instead of a fixed sleep, wait until the account is available
    wait_for_account(&payload.log_id, prover.clone()).await.map_err(|e| {
        error!("Account wait failed: {}", e);
        warp::reject::custom(CustomRejection(e.to_string()))
    })?;

    // Get the user-specific key for signing (to match account creation)
    let user_keystore = KeyChain
        .get_or_create_signing_key(&format!("{}/{}", payload.log_id, SERVICE_ID))
        .map_err(|e| warp::reject::custom(CustomRejection(e.to_string())))?;
    
    let user_sk = SigningKey::Ed25519(Box::new(user_keystore));

    // Convert STH to bytes
    let sth_data = serde_json::to_vec(&payload)
        .map_err(|e| warp::reject::custom(CustomRejection(e.to_string())))?;

    // Create signature bundle
    let hash = Digest::hash(&sth_data);
    let signature = user_sk.sign(&hash.to_bytes());
    let data_signature = SignatureBundle {
        verifying_key: user_sk.verifying_key(),
        signature,
    };

    // Submit the data
    operations::add_data(
        payload.log_id.clone(),
        prover.clone(),
        user_sk,
        sth_data,
        data_signature,
    ).await.map_err(|e| {
        error!("Failed to add data: {}", e);
        warp::reject::custom(CustomRejection(e.to_string()))
    })?;

    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "message": "STH submitted successfully"
    })))
}

#[tokio::main]
async fn main() -> Result<()> {
    std::env::set_var(
        "RUST_LOG",
        "DEBUG,ctclient::internal=off,reqwest=off,hyper=off,tracing=off,sp1_stark=info,jmt=off,p3_dft=off,p3_fri=off,sp1_core_executor=info,sp1_recursion_program=info,p3_merkle_tree=off,sp1_recursion_compiler=off,sp1_core_machine=off",
    );
    pretty_env_logger::init();

    let db = InMemoryDatabase::new();
    let (da_layer, _, _) = InMemoryDataAvailabilityLayer::new(5);

    let keystore_sk = KeyChain
        .get_signing_key(SERVICE_ID)
        .map_err(|e| anyhow!("Error getting key from store: {}", e))?;

    let sk = SigningKey::Ed25519(Box::new(keystore_sk.clone()));

    let cfg = Config {
        prover: true,
        batcher: true,
        webserver: WebServerConfig {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 50525,
        },
        signing_key: sk.clone(),
        verifying_key: sk.verifying_key(),
        start_height: 1,
    };

    let prover = Arc::new(
        Prover::new(
            Arc::new(Box::new(db)),
            Arc::new(da_layer) as Arc<dyn DataAvailabilityLayer>,
            &cfg,
        )
        .unwrap(),
    );

    // Start the prover in the background
    let runner = prover.clone();
    let runner_handle = spawn(async move {
        debug!("starting prover");
        if let Err(e) = runner.run().await {
            log::error!("Error occurred while running prover: {:?}", e);
        }
    });

    // Set up the warp routes
    let submit_sth_route = warp::path!("v1" / "submit_sth")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_prover(prover.clone()))
        .and_then(handle_sth_submission);

    // Add error handling
    let routes = submit_sth_route.recover(|err: warp::Rejection| async move {
        if let Some(custom_err) = err.find::<CustomRejection>() {
            Ok::<WithStatus<Json>, warp::Rejection>(warp::reply::with_status(
                warp::reply::json(&serde_json::json!({
                    "error": custom_err.0
                })),
                warp::http::StatusCode::BAD_REQUEST,
            ))
        } else {
            Ok::<WithStatus<Json>, warp::Rejection>(warp::reply::with_status(
                warp::reply::json(&serde_json::json!({
                    "error": "Internal server error"
                })),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    });

    // Run both the prover and the web server
    let server = warp::serve(routes)
        .run(([127, 0, 0, 1], 50524));

    tokio::select! {
        _ = runner_handle => println!("Prover stopped"),
        _ = server => println!("Server stopped"),
    }

    Ok(())
}
