use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::{
    block::Block,
    blockchain::Blockchain,
    node::{Node, NodeManager},
};
// Request Assisting Structures & Functions
pub struct Config {
    addr: SocketAddr,
}
impl Config {
    pub fn new(mut args: std::env::Args) -> Result<Config, &'static str> {
        if args.len() < 3 {
            return Err("not enough arguments
            usage: blockchain <ip> <port>");
        }
        args.next();
        let ip = match args.next() {
            Some(arg) => arg,
            None => return Err("Didn't get an ip address"),
        };
        let port = match args.next() {
            Some(arg) => arg,
            None => return Err("Didn't get a port number"),
        };
        let addr = format!("{}:{}", ip, port).parse().unwrap();
        Ok(Config { addr })
    }
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}
#[derive(Clone)]
pub struct AppStates {
    pub blockchain: Arc<Mutex<Blockchain>>,
    pub nodes: Arc<Mutex<NodeManager>>,
    pub mining_state: Arc<AtomicBool>,
}

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
    pub blockchain: Option<Blockchain>,
    pub nodes: Option<Vec<Node>>,
    pub is_response: bool,
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
pub enum NewBlockResponse {
    Success,
    SyncRequest,
    NonceError,
    HashError,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Heartbeat {
    pub addr: SocketAddr,
    pub public_key: String,
}

#[derive(Serialize)]
pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
}
// Crypto Assisting Structures & Functions

pub fn private_key_from_string(private_key: &str) -> Result<SecretKey, String> {
    let private_key = private_key.trim().trim_start_matches("0x");
    let private_key = hex::decode(private_key).map_err(|e| e.to_string())?;
    SecretKey::from_slice(&private_key).map_err(|err| format!("Invalid private key: {}", err))
}

pub fn public_key_from_string(public_key: &str) -> Result<PublicKey, String> {
    let public_key = public_key.trim().trim_start_matches("0x");
    let public_key = hex::decode(public_key).map_err(|e| e.to_string())?;
    PublicKey::from_slice(&public_key).map_err(|err| format!("Invalid public key: {}", err))
}

pub fn is_key_match(private_key: &SecretKey, public_key: &PublicKey) -> Result<bool, String> {
    let secp = Secp256k1::new();
    Ok(PublicKey::from_secret_key(&secp, private_key) == *public_key)
}
