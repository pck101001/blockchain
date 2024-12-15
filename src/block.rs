use crate::transaction::Transaction;

pub struct Block {
    index: u64,
    timestamp: u64,
    data: Vec<Transaction>,
    previous_hash: String,
    hash: String,
}
