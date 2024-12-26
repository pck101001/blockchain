use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use crate::{block::Block, blockchain::Blockchain, node::NodeManager};

// Configuration Handling
pub struct Config {
    addr: SocketAddr,
}
impl Config {
    pub fn new(mut args: std::env::Args) -> Result<Config, &'static str> {
        if args.len() < 2 {
            return Err("not enough arguments
            usage: blockchain <port>");
        }
        args.next();
        let port = match args.next() {
            Some(arg) => arg,
            None => return Err("Didn't get a port number"),
        };
        let ip = "0.0.0.0";
        let addr = format!("{}:{}", ip, port).parse().unwrap();
        Ok(Config { addr })
    }
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}
// Shared States Structure
#[derive(Clone)]
pub struct AppStates {
    pub blockchain: Arc<Mutex<Blockchain>>,
    pub nodes: Arc<Mutex<NodeManager>>,
    pub mining_state: Arc<AtomicBool>,
}
// Request and Response Structures
#[derive(Serialize, Deserialize, Debug)]
pub struct ConnectRequest {
    pub des_ip: String,
    pub des_port: u16,
    pub src_ip: String,
    pub src_port: u16,
    pub public_key: String,
    pub is_broadcast: bool,
    pub is_response: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TransactionRequest {
    pub sender_private_key: String,
    pub sender_public_key: String,
    pub receiver_public_key: String,
    pub amount: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SyncRequest {
    pub last_block_index: Option<u64>,
    pub blockchain: Option<Blockchain>,
    pub src_addr: SocketAddr,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RequestWithKey {
    pub public_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NewBlockRequest {
    pub new_block: Block,
    pub last_hash: String,
    pub is_genesis: bool,
}
#[derive(Debug)]
pub enum NewBlockResponse {
    Success,
    SyncRequest,
    NonceError,
    HashError,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MiningStateRequest {
    pub state_control: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Heartbeat {
    pub addr: SocketAddr,
    pub public_key: String,
    pub last_index: Option<u64>,
}

#[derive(Serialize)]
pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
}

// Cryptography Functions
pub fn private_key_from_string(private_key: &str) -> Result<SecretKey, String> {
    let bytes = hex::decode(private_key.trim_start_matches("0x"))
        .map_err(|e| format!("Failed to decode private key: {}", e))?;
    SecretKey::from_slice(&bytes).map_err(|err| format!("Invalid private key: {}", err))
}

pub fn public_key_from_string(public_key: &str) -> Result<PublicKey, String> {
    let bytes = hex::decode(public_key.trim_start_matches("0x"))
        .map_err(|e| format!("Failed to decode public key: {}", e))?;
    PublicKey::from_slice(&bytes).map_err(|err| format!("Invalid public key: {}", err))
}

pub fn is_key_match(private_key: &SecretKey, public_key: &PublicKey) -> Result<bool, String> {
    let secp = Secp256k1::new();
    match PublicKey::from_secret_key(&secp, private_key) == *public_key {
        true => Ok(true),
        false => Err("Key pair does not match".to_string()),
    }
}
