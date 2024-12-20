use secp256k1::ecdsa::Signature;
use secp256k1::hashes::{sha256, Hash};
use secp256k1::{Message, Secp256k1};
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::SystemTime;

use crate::utils::public_key_from_string;
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Transaction {
    raw_data: RawTransaction,
    txid: String,
    signature: Option<Signature>,
    block_index: Option<u64>,
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
        let sig = raw_transaction.sign(private_key);
        Transaction {
            raw_data: raw_transaction,
            txid,
            signature: Some(sig),
            block_index: None,
        }
    }

    pub fn coinbase_reward(receiver: &str) -> Self {
        let raw_transaction = RawTransaction {
            sender: "0".to_string(),
            receiver: receiver.to_owned(),
            amount: 10.0,
            time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
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
        let is_txid_valid = self.txid == self.raw_data.hash();
        if self.raw_data.is_coinbase {
            if is_txid_valid {
                return Ok(true);
            } else {
                return Err("Txid Not Valid as Coinbase".to_string());
            }
        }
        let public_key = public_key_from_string(&self.raw_data.sender).unwrap();
        let signature = self.signature.unwrap();
        let is_signature_valid = secp.verify_ecdsa(&msg, &signature, &public_key) == Ok(());
        if is_signature_valid {
            if is_txid_valid {
                Ok(true)
            } else {
                Err("Txid Not Valid".to_string())
            }
        } else {
            Err("Signature Not Valid".to_string())
        }
    }
    pub fn txid(&self) -> String {
        self.txid.clone()
    }
    pub fn raw_data(&self) -> RawTransaction {
        self.raw_data.clone()
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
    new_transaction: Transaction,
    nodes: Vec<SocketAddr>,
) -> Result<(), reqwest::Error> {
    for node in nodes.iter().skip(1) {
        let client = reqwest::Client::new();
        let res = client
            .post(format!("http://{}/transaction/broadcast", node))
            .json(&new_transaction)
            .send()
            .await;
        if let Err(e) = res {
            return Err(e);
        }
    }
    Ok(())
}
