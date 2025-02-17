// src/operations.rs
use std::sync::Arc;
use anyhow::{Result, anyhow};
use log::debug;
use prism_common::{
    account::Account,
    digest::Digest,
    operation::{Operation, ServiceChallenge, ServiceChallengeInput, SignatureBundle},
};
use prism_keys::SigningKey;
use prism_prover::Prover;
use prism_tree::AccountResponse::Found;
use keystore_rs::{KeyChain, KeyStore};

use crate::SERVICE_ID;

pub async fn register_service(prover: Arc<Prover>, service_sk: SigningKey) -> Result<()> {
    // First, check if service is already registered
    if let Found(_, _) = prover.get_account(&SERVICE_ID.to_string()).await? {
        debug!("Service already registered");
        return Ok(());
    }

    let vk = service_sk.verifying_key();

    // Create RegisterService operation
    let register_op = Operation::RegisterService {
        id: SERVICE_ID.to_string(),
        creation_gate: ServiceChallenge::Signed(vk.clone()),
        key: vk,
    };

    // Create empty account and prepare transaction
    let service_account = Account::default();
    let register_tx = service_account.prepare_transaction(
        SERVICE_ID.to_string(),
        register_op,
        &service_sk
    )?;

    debug!("Registering CT monitor service");
    prover.validate_and_queue_update(register_tx.clone()).await?;
    
    debug!("Successfully registered service");
    Ok(())
}

pub async fn create_account(
    log_id: String,
    prover: Arc<Prover>,
    service_sk: SigningKey,
) -> Result<Account> {
    // Check if account exists
    if let Found(account, _) = prover.get_account(&log_id).await? {
        debug!("Account for CT log {} already exists", log_id);
        return Ok(*account);
    }

    // Create keypair for the CT log account
    let log_keystore = KeyChain
        .get_or_create_signing_key(&format!("{}/{}", log_id, SERVICE_ID))
        .map_err(|e| anyhow!("Error getting key from store: {}", e))?;
    
    let log_sk = SigningKey::Ed25519(Box::new(log_keystore));
    let log_vk = log_sk.verifying_key();

    // Create signature for account creation
    let hash = Digest::hash_items(&[
        log_id.as_bytes(),
        SERVICE_ID.as_bytes(),
        &log_vk.to_bytes(),
    ]);
    let signature = service_sk.sign(&hash.to_bytes());

    // Create account operation
    let create_acc_op = Operation::CreateAccount {
        id: log_id.clone(),
        service_id: SERVICE_ID.to_string(),
        challenge: ServiceChallengeInput::Signed(signature),
        key: log_vk,
    };

    // Prepare and submit transaction
    let mut account = Account::default();
    let create_acc_tx = account.prepare_transaction(log_id.clone(), create_acc_op, &log_sk)?;

    debug!("Creating account for CT log {}", log_id);
    prover.validate_and_queue_update(create_acc_tx.clone()).await?;

    account.process_transaction(&create_acc_tx)?;
    debug!("Successfully created account for CT log {}", log_id);
    Ok(account)
}

pub async fn add_data(
    user_id: String,
    prover: Arc<Prover>,
    signing_key: SigningKey,
    data: Vec<u8>,
) -> Result<Account> {
    if let Found(account, _) = prover.get_account(&user_id).await? {
        // Generate signature for the data
        let hash = Digest::hash(&data);
        let signature = signing_key.sign(&hash.to_bytes());

        // Create SignatureBundle with verifying key and signature
        let data_signature = SignatureBundle {
            verifying_key: signing_key.verifying_key(),
            signature,
        };

        // Create AddData operation
        let add_data_op = Operation::AddData {
            data,
            data_signature,
        };

        let mut account = account.clone();
        let add_data_tx =
            account.prepare_transaction(user_id.clone(), add_data_op, &signing_key)?;

        debug!("Submitting STH data to account {}", &user_id);
        prover
            .clone()
            .validate_and_queue_update(add_data_tx.clone())
            .await?;

        account.process_transaction(&add_data_tx)?;
        return Ok(*account);
    }

    Err(anyhow!("Account {} not found", &user_id))
}