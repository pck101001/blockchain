use crate::transaction::Transaction;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    index: u64,
    timestamp: u128,
    previous_hash: String,
    merkle_hash: String,
    nonce: u64,
    miner: String,
    mining_difficulty: usize,

    data: Vec<Transaction>,
}

impl Block {
    pub fn new(
        index: u64,
        timestamp: u128,
        previous_hash: String,
        nonce: u64,
        data: Vec<Transaction>,
        miner: String,
        mining_difficulty: usize,
    ) -> Block {
        let merkle_hash = calculate_merkle_root(&data);
        let mut data_with_index = data;
        data_with_index
            .iter_mut()
            .for_each(|tx| tx.update_block_index(index));
        Block {
            index,
            timestamp,
            previous_hash,
            merkle_hash,
            nonce,
            miner,
            mining_difficulty,
            data: data_with_index,
        }
    }

    pub fn genesis() -> Block {
        Block {
            index: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis(),
            previous_hash: String::from("0"),
            merkle_hash: String::from("0"),
            nonce: 0,
            data: Vec::new(),
            miner: String::from("0"),
            mining_difficulty: 0,
        }
    }

    pub fn block_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.index.to_string());
        hasher.update(self.timestamp.to_string());
        hasher.update(&self.previous_hash);
        hasher.update(&self.merkle_hash);
        hasher.update(self.nonce.to_string());
        hex::encode(hasher.finalize())
    }

    pub fn index(&self) -> u64 {
        self.index
    }

    pub fn data(&self) -> &[Transaction] {
        &self.data
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn timestamp(&self) -> u128 {
        self.timestamp
    }
}

pub fn calculate_merkle_root(transactions: &[Transaction]) -> String {
    if transactions.is_empty() {
        return String::from("");
    }

    let mut hashes: Vec<String> = transactions
        .iter()
        .map(|tx| tx.txid().to_string())
        .collect();

    while hashes.len() > 1 {
        if hashes.len() % 2 != 0 {
            hashes.push(hashes.last().unwrap().clone());
        }
        let new_hashes: Vec<String> = hashes
            .chunks(2)
            .map(|chunk| {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                hasher.update(&chunk[1]);
                hex::encode(hasher.finalize())
            })
            .collect();
        hashes = new_hashes;
    }
    hashes[0].clone()
}
