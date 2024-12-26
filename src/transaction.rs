use secp256k1::ecdsa::Signature;
use secp256k1::hashes::{sha256, Hash};
use secp256k1::{Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::utils::public_key_from_string;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Transaction {
    pub raw_data: RawTransaction,
    pub txid: String,
    pub signature: Option<Signature>,
    pub block_index: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RawTransaction {
    pub sender: String,
    pub receiver: String,
    pub amount: f64,
    pub time: u128,
    pub is_coinbase: bool,
}

impl Transaction {
    pub fn new(raw_transaction: RawTransaction, private_key: &SecretKey) -> Self {
        let txid = raw_transaction.hash();
        let signature = raw_transaction.sign(private_key);
        Transaction {
            raw_data: raw_transaction,
            txid,
            signature: Some(signature),
            block_index: None,
        }
    }

    pub fn coinbase_reward(receiver: &str) -> Self {
        let raw_transaction = RawTransaction {
            sender: String::new(), // Empty string for coinbase transactions
            receiver: receiver.to_string(),
            amount: 10.0,
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis(),
            is_coinbase: true,
        };
        let txid = raw_transaction.hash();
        Transaction {
            raw_data: raw_transaction,
            txid,
            signature: None,
            block_index: None,
        }
    }

    pub fn verify(&self) -> Result<bool, String> {
        let secp = Secp256k1::new();
        let msg = Message::from_digest(
            sha256::Hash::hash(serde_json::to_string(&self.raw_data).unwrap().as_bytes())
                .to_byte_array(),
        );

        if self.raw_data.is_coinbase {
            return if self.txid == self.raw_data.hash() {
                Ok(true)
            } else {
                Err("Invalid coinbase transaction ID".to_string())
            };
        }

        let public_key = public_key_from_string(&self.raw_data.sender)
            .map_err(|e| format!("Invalid sender public key: {}", e))?;
        let signature = self.signature.as_ref().ok_or("Missing signature")?;

        if secp.verify_ecdsa(&msg, signature, &public_key).is_ok() {
            if self.txid == self.raw_data.hash() {
                Ok(true)
            } else {
                Err("Invalid transaction ID".to_string())
            }
        } else {
            Err("Invalid signature".to_string())
        }
    }

    pub fn txid(&self) -> &str {
        &self.txid
    }

    pub fn raw_data(&self) -> &RawTransaction {
        &self.raw_data
    }

    pub fn update_block_index(&mut self, index: u64) {
        self.block_index = Some(index);
    }
}

impl RawTransaction {
    pub fn sign(&self, private_key: &SecretKey) -> Signature {
        let secp = Secp256k1::new();
        let msg = Message::from_digest(
            sha256::Hash::hash(serde_json::to_string(&self).unwrap().as_bytes()).to_byte_array(),
        );
        secp.sign_ecdsa(&msg, private_key)
    }

    pub fn hash(&self) -> String {
        let digest = sha256::Hash::hash(serde_json::to_string(self).unwrap().as_bytes());
        format!("{:x}", digest)
    }
}

pub async fn broadcast_new_transaction(
    new_transaction: &Transaction,
    nodes: &[SocketAddr],
) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();
    for node in nodes.iter().skip(1) {
        client
            .post(format!("http://{}/transaction/broadcast", node))
            .json(&new_transaction)
            .send()
            .await?;
    }
    Ok(())
}
