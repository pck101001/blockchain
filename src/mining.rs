use crate::block::Block;
use crate::utils::AppStates;
use crate::utils::NewBlockRequest;
use rand::Rng;
use reqwest;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::time::{interval, Duration};

pub async fn mine_block(states: AppStates) {
    let mut rng = rand::thread_rng();
    let difficulty = Arc::new(AtomicUsize::new(4));
    let last_hash = Arc::new(Mutex::new(String::new()));

    let difficulty_clone = difficulty.clone();
    let last_hash_clone = last_hash.clone();
    let nodes_clone = states.nodes.clone();
    let mining_state_clone = states.mining_state.clone();
    tokio::spawn(async move {
        let mut nodes_update_interval = interval(Duration::from_secs(5));
        loop {
            nodes_update_interval.tick().await;
            if !mining_state_clone.load(Ordering::SeqCst) {
                break;
            }
            let nodes_count = { nodes_clone.lock().unwrap().get_nodes_addr().len() };
            difficulty_clone.store(calculate_difficulty(nodes_count), Ordering::Relaxed);
        }
    });
    let mining_state_clone_ = states.mining_state.clone();
    let blockchain_clone = states.blockchain.clone();
    tokio::spawn(async move {
        let mut hash_update_interval = interval(Duration::from_secs(1));
        loop {
            hash_update_interval.tick().await;
            if !mining_state_clone_.load(Ordering::SeqCst) {
                break;
            }
            let mut hash = last_hash_clone.lock().unwrap();
            *hash = blockchain_clone.lock().unwrap().last_hash();
        }
    });
    loop {
        if !states.mining_state.load(Ordering::SeqCst) {
            break;
        }
        let nonce = rng.gen::<u64>();
        let nodes_count = { states.nodes.lock().unwrap().get_nodes_addr().len() };
        let last_hash_value = { last_hash.lock().unwrap().clone() };
        if verify_answer(&last_hash_value, nodes_count, nonce) {
            let mut blockchain = states.blockchain.lock().unwrap();
            let current_difficulty = difficulty.load(Ordering::Relaxed);
            let miner = { states.nodes.lock().unwrap().get_local_public_key() };
            let new_block = blockchain.mine_block(&miner, nonce, current_difficulty);
            let nodes = { states.nodes.lock().unwrap().get_nodes_addr() };
            blockchain.add_block(new_block.clone());
            println!("New Block Mined, index: {}", new_block.index());
            tokio::spawn(async move {
                broadcast_new_block(new_block, last_hash_value, nodes, false).await;
            });
        }
    }
}

pub async fn broadcast_new_block(
    new_block: Block,
    last_hash: String,
    nodes: Vec<SocketAddr>,
    is_genesis: bool,
) {
    for node in nodes.iter().skip(1) {
        let client = reqwest::Client::new();
        let _ = client
            .post(format!("http://{}/new_block", node))
            .json(&NewBlockRequest {
                new_block: new_block.clone(),
                last_hash: last_hash.clone(),
                is_genesis,
            })
            .send()
            .await;
    }
}
pub fn verify_answer(last_hash: &String, nodes_count: usize, nonce: u64) -> bool {
    let hash = calculate_hash(last_hash, nonce);
    let difficulty = calculate_difficulty(nodes_count);
    if hash.starts_with(&"0".repeat(10 - difficulty)) {
        println!("Hash: {}", hash);
        return true;
    }
    false
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
