use crate::block::Block;
use crate::transaction::Transaction;

pub struct Blockchain {
    chain: Vec<Block>,
    pending_transactions: Vec<Transaction>,
}

impl Blockchain {
    pub fn new() -> Self {
        let chain = Vec::new();
        let pending_transactions = Vec::new();
        Blockchain {
            chain,
            pending_transactions,
        }
    }

    pub fn add_block(&mut self, block: Block) {
        self.chain.push(block);
    }

    pub fn add_pending_transaction(&mut self, transaction: Transaction) {
        self.pending_transactions.push(transaction);
    }
}
