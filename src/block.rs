use crate::transaction::Transaction;
use hex;
use sha2::{Digest, Sha256};

pub struct Block {
    index: u64,
    timestamp: u128,
    previous_hash: String,
    merkle_hash: String,
    nonce: u64,
    miner: String,

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
    ) -> Block {
        let merkle_hash = calculate_merkle_root(&data);
        let mut data_indexed = data.clone();
        for tx in data_indexed.iter_mut() {
            tx.update_block_index(index);
        }
        Block {
            index,
            timestamp,
            previous_hash,
            merkle_hash,
            nonce,
            data: data_indexed,
            miner,
        }
    }
    pub fn block_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.index.to_string());
        hasher.update(self.timestamp.to_string());
        hasher.update(self.previous_hash.clone());
        hasher.update(self.merkle_hash.clone());
        hasher.update(self.nonce.to_string());
        hex::encode(hasher.finalize())
    }
}
pub fn calculate_merkle_root(transactions: &Vec<Transaction>) -> String {
    if transactions.is_empty() {
        return String::from("");
    }
    let mut hashes = transactions
        .iter()
        .map(|tx| tx.txid())
        .collect::<Vec<String>>();

    while hashes.len() > 1 {
        if hashes.len() % 2 != 0 {
            let last = hashes.last().unwrap().clone();
            hashes.push(last.clone());
        }
        let mut new_hashes = Vec::new();
        for chunk in hashes.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(chunk[0].clone());
            hasher.update(chunk[1].clone());
            let hash = hasher.finalize();
            new_hashes.push(hex::encode(hash));
        }
        hashes = new_hashes;
    }
    hashes[0].clone()
}
