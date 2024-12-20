use crate::block::Block;
use crate::transaction::Transaction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;
#[derive(Serialize, Deserialize, Debug, Clone)]
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

    pub fn add_pending_transaction(&mut self, transaction: Transaction) -> Result<(), &str> {
        if self.is_chain_empty() {
            return Err("Add Genesis Block First!");
        }
        let last_block_time = self.chain.last().unwrap().timestamp();
        if transaction.raw_data().time < last_block_time {
            return Err("Transaction is too old");
        }
        let txid = transaction.txid();
        if self.pending_transactions.iter().any(|tx| tx.txid() == txid) {
            return Err("Transaction already exists");
        }
        if !transaction.raw_data().is_coinbase
            && self.total_balance(&transaction.raw_data().sender) < transaction.raw_data().amount
        {
            return Err("Insufficient balance");
        }
        self.pending_transactions.push(transaction);
        Ok(())
    }

    pub fn add_genesis_block(&mut self, block: Block) {
        if !self.chain.is_empty() {
            println!("Genesis block already exists");
        } else {
            self.chain.push(block);
        }
    }

    pub fn balance(&self, public_key: &str) -> (f64, f64) {
        let fixed_balance = self
            .utxo_set
            .get(public_key)
            .map(|bills| bills.iter().map(|(_, amount)| amount).sum())
            .unwrap_or(0.0);
        let pending_balance = self
            .pending_transactions
            .iter()
            .filter(|tx| {
                tx.raw_data().sender == *public_key || tx.raw_data().receiver == *public_key
            })
            .map(|tx| {
                if tx.raw_data().sender == *public_key && tx.raw_data().receiver != *public_key {
                    -tx.raw_data().amount
                } else if tx.raw_data().receiver == *public_key
                    && tx.raw_data().sender != *public_key
                {
                    tx.raw_data().amount
                } else {
                    0.0
                }
            })
            .sum();
        (fixed_balance, pending_balance)
    }

    pub fn total_balance(&self, public_key: &String) -> f64 {
        let (fixed_balance, pending_balance) = self.balance(public_key);
        fixed_balance + pending_balance
    }

    pub fn last_index(&self) -> u64 {
        if self.chain.is_empty() {
            panic!("Add Genesis Block First!");
        }
        self.chain.last().unwrap().index()
    }

    pub fn last_hash(&self) -> String {
        if self.chain.is_empty() {
            panic!("Add Genesis Block First!");
        }
        self.chain.last().unwrap().block_hash()
    }

    pub fn last_block(&self) -> Block {
        if self.chain.is_empty() {
            panic!("Add Genesis Block First!");
        }
        self.chain.last().unwrap().clone()
    }

    pub fn add_block(&mut self, block: Block) {
        self.chain.push(block.clone());
        self.update_utxo_set(&block);
        for tx in block.data().iter() {
            let txid = tx.txid();
            self.pending_transactions.retain(|tx| tx.txid() != txid);
        }
        println!("Block added: {:?}", block);
    }

    pub fn mine_block(&mut self, miner: &str, nonce: u64, difficulty: usize) -> Block {
        let coinbase_tx = Transaction::coinbase_reward(miner);
        let index = self.chain.len() as u64;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let previous_hash = self.chain.last().unwrap().block_hash();
        let mut data = vec![coinbase_tx];
        data.append(&mut self.pending_transactions.clone());
        Block::new(
            index,
            timestamp,
            previous_hash,
            nonce,
            data,
            String::from(miner),
            difficulty,
        )
    }

    pub fn is_chain_empty(&self) -> bool {
        self.chain.is_empty()
    }

    pub fn is_pending_empty(&self) -> bool {
        self.pending_transactions.is_empty()
    }

    fn update_utxo_set(&mut self, block: &Block) {
        for tx in block.data().iter() {
            let tx_data = tx.raw_data();
            let sender = tx_data.sender.clone();
            let receiver = tx_data.receiver.clone();
            let amount = tx_data.amount;
            let txid = tx.txid();
            let bills = self.utxo_set.entry(sender).or_default();
            bills.push((txid.clone(), -amount));
            let bills = self.utxo_set.entry(receiver).or_default();
            bills.push((txid.clone(), amount));
        }
        println!("UTXO Set Updated: {:?}", self.utxo_set);
    }
}
