use crate::block::Block;
use crate::transaction::Transaction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Blockchain {
    chain: Vec<Block>,
    utxo_set: HashMap<String, Vec<(String, f64)>>,
    pending_transactions: Vec<Transaction>,
}

impl Blockchain {
    pub fn new() -> Self {
        Blockchain {
            chain: Vec::new(),
            pending_transactions: Vec::new(),
            utxo_set: HashMap::new(),
        }
    }

    pub fn chain(&self) -> &[Block] {
        &self.chain
    }

    pub fn pending_transactions(&self) -> &[Transaction] {
        &self.pending_transactions
    }

    pub fn add_pending_transaction(
        &mut self,
        transaction: Transaction,
    ) -> Result<(), &'static str> {
        if self.is_chain_empty() {
            return Err("Add Genesis Block First!");
        }
        let last_block_time = self.chain.last().unwrap().timestamp();
        if transaction.raw_data().time < last_block_time {
            return Err("Transaction is too old");
        }
        if self
            .pending_transactions
            .iter()
            .any(|tx| tx.txid() == transaction.txid())
        {
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
        if self.chain.is_empty() {
            self.chain.push(block);
        } else {
            log::warn!("Genesis block already exists, ignoring new block");
        }
    }

    pub fn balance(&self, public_key: &str) -> (f64, f64) {
        let fixed_balance = self
            .utxo_set
            .get(public_key)
            .map_or(0.0, |bills| bills.iter().map(|(_, amount)| amount).sum());
        let pending_balance = self.pending_transactions.iter().fold(0.0, |acc, tx| {
            acc + if tx.raw_data().sender == public_key {
                -tx.raw_data().amount
            } else if tx.raw_data().receiver == public_key {
                tx.raw_data().amount
            } else {
                0.0
            }
        });
        (fixed_balance, pending_balance)
    }

    pub fn total_balance(&self, public_key: &str) -> f64 {
        let (fixed, pending) = self.balance(public_key);
        fixed + pending
    }

    pub fn last_index(&self) -> u64 {
        self.chain.last().map(|b| b.index()).unwrap_or_else(|| {
            log::error!("Attempted to access last index of an empty blockchain");
            0
        })
    }

    pub fn last_hash(&self) -> String {
        self.chain
            .last()
            .map(|b| b.block_hash())
            .unwrap_or_else(|| {
                log::error!("Attempted to access last hash of an empty blockchain");
                String::from("0")
            })
    }

    pub fn last_block(&self) -> Option<&Block> {
        self.chain.last()
    }

    pub fn replace_blockchain(&mut self, new_blockchain: &Blockchain) {
        if new_blockchain.chain.len() > self.chain.len() {
            *self = new_blockchain.clone();
        }
    }

    pub fn add_block(&mut self, block: Block) {
        self.chain.push(block.clone());
        self.update_utxo_set(&block);
        self.pending_transactions
            .retain(|tx| !block.data().iter().any(|b_tx| b_tx.txid() == tx.txid()));
        log::info!("Block added: {:?}", block);
    }

    pub fn mine_block(&mut self, miner: &str, nonce: u64, difficulty: usize) -> Block {
        let coinbase_tx = Transaction::coinbase_reward(miner);
        let index = self.chain.len() as u64;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();
        let previous_hash = self.last_hash();
        let mut data = vec![coinbase_tx];
        data.append(&mut self.pending_transactions.clone());
        Block::new(
            index,
            timestamp,
            previous_hash,
            nonce,
            data,
            miner.to_string(),
            difficulty,
        )
    }

    pub fn is_chain_empty(&self) -> bool {
        self.chain.is_empty()
    }

    fn update_utxo_set(&mut self, block: &Block) {
        for tx in block.data() {
            let tx_data = tx.raw_data();
            let sender = &tx_data.sender;
            let receiver = &tx_data.receiver;
            let amount = tx_data.amount;
            let txid = tx.txid().to_string();

            self.utxo_set
                .entry(sender.to_string())
                .or_default()
                .push((txid.clone(), -amount));
            self.utxo_set
                .entry(receiver.to_string())
                .or_default()
                .push((txid, amount));
        }
        log::debug!("UTXO Set Updated: {:?}", self.utxo_set);
    }
}
