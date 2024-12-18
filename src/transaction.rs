use secp256k1::ecdsa::Signature;
use secp256k1::hashes::{sha256, Hash};
use secp256k1::{Message, Secp256k1};
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

use crate::utils::public_key_from_string;
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Transaction {
    row_data: RowTransaction,
    txid: String,
    signature: Option<Signature>,
    block_index: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RowTransaction {
    pub sender: String,
    pub receiver: String,
    pub amount: f64,
    pub time: u128,
}

impl Transaction {
    pub fn new(row_transaction: RowTransaction, private_key: &SecretKey) -> Self {
        let txid = row_transaction.hash();
        let sig = row_transaction.sign(private_key);
        Transaction {
            row_data: row_transaction,
            txid,
            signature: Some(sig),
            block_index: None,
        }
    }
    pub fn verify(&self) -> Result<bool, String> {
        let secp = Secp256k1::new();
        let msg = Message::from_digest(
            sha256::Hash::hash(serde_json::to_string(&self.row_data).unwrap().as_bytes())
                .to_byte_array(),
        );
        let public_key = public_key_from_string(&self.row_data.sender).unwrap();
        let signature = self.signature.unwrap();
        let is_signature_valid = secp.verify_ecdsa(&msg, &signature, &public_key) == Ok(());
        let is_txid_valid = self.txid == self.row_data.hash();
        if is_signature_valid && is_txid_valid {
            Ok(true)
        } else {
            Err("Invalid Transaction".to_string())
        }
    }
    pub fn txid(&self) -> String {
        self.txid.clone()
    }
    pub fn update_block_index(&mut self, index: u64) {
        self.block_index = Some(index);
    }
}

impl RowTransaction {
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
