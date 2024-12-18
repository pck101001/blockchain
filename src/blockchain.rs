use crate::block::Block;
use crate::transaction::Transaction;
use std::collections::HashMap;
use std::time::SystemTime;

pub struct Blockchain {
    chain: Vec<Block>,
    utxo_set: HashMap<String, Vec<(String, f64)>>,
    pending_transactions: Vec<Transaction>,
}

impl Blockchain {
    pub fn new() -> Self {
        let chain = Vec::new();
        let pending_transactions = Vec::new();
        let utxo_set = HashMap::new();
        Blockchain {
            chain,
            pending_transactions,
            utxo_set,
        }
    }

    pub fn add_block(&mut self, block: Block) {
        self.chain.push(block);
    }

    pub fn add_pending_transaction(&mut self, transaction: Transaction) {
        self.pending_transactions.push(transaction);
    }

    pub fn add_genesis_block(&mut self, block: Block) {
        if !self.chain.is_empty() {
            println!("Genesis block already exists");
        } else {
            self.chain.push(block);
        }
    }

    fn mine_block(&mut self, miner: &String, nonce: u64) {
        let index = self.chain.len() as u64;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let previous_hash = self.chain.last().unwrap().block_hash();
        let data = self.pending_transactions.clone();
        let mut block = Block::new(index, timestamp, previous_hash, nonce, data, miner.clone());
    }
}
