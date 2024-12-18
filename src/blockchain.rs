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

    pub fn balance(&self, public_key: &String) -> f64 {
        let bills = self.utxo_set.get(public_key).unwrap();
        bills.iter().map(|(_, amount)| amount).sum()
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

    pub fn mine_block(&mut self, miner: &str, nonce: u64, difficulty: usize) {
        let index = self.chain.len() as u64;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let previous_hash = self.chain.last().unwrap().block_hash();
        let data = self.pending_transactions.clone();
        let block = Block::new(
            index,
            timestamp,
            previous_hash,
            nonce,
            data,
            String::from(miner),
            difficulty,
        );
        self.chain.push(block.clone());
        println!("Block added: {:?}", block);
        self.update_utxo_set(&block);
        self.pending_transactions.clear();
    }
    pub fn add_block(&mut self, block: Block) {
        self.chain.push(block.clone());
        self.update_utxo_set(&block);
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
    }
}
