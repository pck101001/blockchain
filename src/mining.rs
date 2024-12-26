use crate::block::Block;
use crate::blockchain::Blockchain;
use crate::node::NodeManager;
use crate::utils::{AppStates, NewBlockRequest};
use rand::Rng;
use reqwest;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::time::{interval, Duration};

pub async fn mine_block(states: AppStates) {
    let mut rng = rand::thread_rng();
    let difficulty = Arc::new(AtomicUsize::new(4));
    let last_hash = Arc::new(Mutex::new(String::new()));

    // Update difficulty based on node count
    let difficulty_clone = Arc::clone(&difficulty);
    let nodes_clone = Arc::clone(&states.nodes);
    let mining_state_clone = Arc::clone(&states.mining_state);
    tokio::spawn(update_difficulty(
        difficulty_clone,
        nodes_clone,
        mining_state_clone,
    ));

    // Update last hash
    let last_hash_clone = Arc::clone(&last_hash);
    let blockchain_clone = Arc::clone(&states.blockchain);
    let mining_state_clone_ = Arc::clone(&states.mining_state);
    tokio::spawn(update_last_hash(
        last_hash_clone,
        blockchain_clone,
        mining_state_clone_,
    ));

    // Main mining loop
    loop {
        if !states.mining_state.load(Ordering::SeqCst) {
            break;
        }
        let nonce = rng.gen::<u64>();
        let nodes_count = states.nodes.lock().unwrap().get_nodes_addr().len();
        let last_hash_value = last_hash.lock().unwrap().clone();
        if verify_answer(&last_hash_value, nodes_count, nonce) {
            let mut blockchain = states.blockchain.lock().unwrap();
            let current_difficulty = difficulty.load(Ordering::Relaxed);
            let miner = states.nodes.lock().unwrap().get_local_public_key();
            let new_block = blockchain.mine_block(&miner, nonce, current_difficulty);
            blockchain.add_block(new_block.clone());
            log::info!("New Block Mined, index: {}", new_block.index());
            let nodes = states.nodes.lock().unwrap().get_nodes_addr();
            tokio::spawn(broadcast_new_block(
                new_block,
                last_hash_value,
                nodes,
                false,
            ));
        }
    }
}

async fn update_difficulty(
    difficulty: Arc<AtomicUsize>,
    nodes: Arc<Mutex<NodeManager>>,
    mining_state: Arc<AtomicBool>,
) {
    let mut interval = interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        if !mining_state.load(Ordering::SeqCst) {
            break;
        }
        let nodes_count = nodes.lock().unwrap().get_nodes_addr().len();
        difficulty.store(calculate_difficulty(nodes_count), Ordering::Relaxed);
    }
}

async fn update_last_hash(
    last_hash: Arc<Mutex<String>>,
    blockchain: Arc<Mutex<Blockchain>>,
    mining_state: Arc<AtomicBool>,
) {
    let mut interval = interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        if !mining_state.load(Ordering::SeqCst) {
            break;
        }
        let mut hash = last_hash.lock().unwrap();
        *hash = blockchain.lock().unwrap().last_hash();
    }
}

pub async fn broadcast_new_block(
    new_block: Block,
    last_hash: String,
    nodes: Vec<SocketAddr>,
    is_genesis: bool,
) {
    let client = reqwest::Client::new();
    for node in nodes.iter().skip(1) {
        if let Err(e) = client
            .post(format!("http://{}/new_block", node))
            .json(&NewBlockRequest {
                new_block: new_block.clone(),
                last_hash: last_hash.clone(),
                is_genesis,
            })
            .send()
            .await
        {
            log::warn!("Failed to broadcast new block to {}: {:?}", node, e);
        }
    }
}

pub fn verify_answer(last_hash: &String, nodes_count: usize, nonce: u64) -> bool {
    let hash = calculate_hash(last_hash, nonce);
    let difficulty = calculate_difficulty(nodes_count);
    hash.starts_with(&"0".repeat(10 - difficulty))
}

pub fn calculate_hash(last_hash: &String, nonce: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", last_hash, nonce));
    format!("{:x}", hasher.finalize())
}

pub fn calculate_difficulty(nodes_count: usize) -> usize {
    if nodes_count < 5 {
        5
    } else {
        3
    }
}
