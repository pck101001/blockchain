use crate::block::Block;
use crate::transaction::Transaction;

pub struct Blockchain {
    chain: Vec<Block>,
}

impl Blockchain {
    pub fn new() -> Self {
        let mut chain = Vec::new();
        Blockchain { chain }
    }

    pub fn add_block(&mut self, block: Block) {
        self.chain.push(block);
    }
}
