use crate::utils::{
    is_key_match, private_key_from_string, public_key_from_string, AppStates, ConnectRequest,
    Heartbeat, KeyPair, MiningStateRequest, NewBlockRequest, NewBlockResponse, RequestWithKey,
    SyncRequest, TransactionRequest,
};
use crate::{
    block::Block,
    blockchain::Blockchain,
    mining,
    node::NodeManager,
    transaction,
    transaction::{RawTransaction, Transaction},
};
use axum::{extract::State, response::IntoResponse, Json};
use reqwest;
use secp256k1::{generate_keypair, rand};
use std::time::SystemTime;
use std::{
    net::SocketAddr,
    sync::atomic::Ordering,
    sync::{Arc, Mutex},
};
use tokio::time::{interval, Duration};

pub async fn transaction_submit_handler(
    State(states): State<AppStates>,
    Json(request): Json<TransactionRequest>,
) -> impl IntoResponse {
    log::info!("Submitted transaction: {:?}", request);
    match pack_transaction(request) {
        Ok(transaction) => {
            let mut blockchain = states.blockchain.lock().unwrap();
            match blockchain.add_pending_transaction(transaction.clone()) {
                Ok(_) => {
                    log::info!("Transaction added: {:?}", transaction);
                    let nodes = states.nodes.lock().unwrap().get_nodes_addr();
                    tokio::spawn(async move {
                        if let Err(e) =
                            transaction::broadcast_new_transaction(&transaction, &nodes).await
                        {
                            log::error!("Error broadcasting transaction: {:?}", e);
                        }
                    });
                    Json(serde_json::json!({"status":"Transaction submitted"}))
                }
                Err(e) => {
                    log::error!("Error adding transaction: {:?}", e);
                    Json(serde_json::json!({"status":e}))
                }
            }
        }
        Err(e) => {
            log::error!("Error packing transaction: {:?}", e);
            Json(serde_json::json!({"status":e}))
        }
    }
}

fn pack_transaction(transaction_request: TransactionRequest) -> Result<Transaction, &'static str> {
    let sender_private_key = private_key_from_string(&transaction_request.sender_private_key)
        .map_err(|_| "Invalid sender private key")?;
    let sender_public_key = public_key_from_string(&transaction_request.sender_public_key)
        .map_err(|_| "Invalid sender public key")?;
    let receiver_public_key = public_key_from_string(&transaction_request.receiver_public_key)
        .map_err(|_| "Invalid receiver public key")?;

    if is_key_match(&sender_private_key, &sender_public_key).is_err() {
        return Err("Private key does not match public key");
    }
    if sender_public_key == receiver_public_key {
        return Err("Sender and receiver public keys are the same");
    }

    let raw_transaction = RawTransaction {
        sender: format!("0x{}", hex::encode(sender_public_key.serialize())),
        receiver: format!("0x{}", hex::encode(receiver_public_key.serialize())),
        amount: transaction_request.amount,
        time: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
        is_coinbase: false,
    };
    Ok(Transaction::new(raw_transaction, &sender_private_key))
}

pub async fn transaction_broadcast_handler(
    State(states): State<AppStates>,
    Json(transaction): Json<Transaction>,
) -> impl IntoResponse {
    if let Err(e) = transaction.verify() {
        log::warn!("Transaction verification failed: {}", e);
        return Json(serde_json::json!({"status":e}));
    }

    let mut blockchain = states.blockchain.lock().unwrap();
    match blockchain.add_pending_transaction(transaction.clone()) {
        Ok(_) => {
            log::info!("Broadcast transaction added: {:?}", transaction);
            Json(serde_json::json!({"status":"broadcast transaction added"}))
        }
        Err(e) => {
            log::error!("Error adding broadcast transaction: {:?}", e);
            Json(serde_json::json!({"status":e}))
        }
    }
}

pub async fn connect_handler(
    State(states): State<AppStates>,
    Json(request): Json<ConnectRequest>,
) -> impl IntoResponse {
    let des_addr = SocketAddr::new(request.des_ip.parse().unwrap(), request.des_port);
    let src_addr = SocketAddr::new(request.src_ip.parse().unwrap(), request.src_port);
    log::info!(
        "New POST Request received: src: {:?}, des: {:?}",
        src_addr,
        des_addr
    );

    let local_addr = { states.nodes.lock().unwrap().get_local_addr() };
    let local_public_key = { states.nodes.lock().unwrap().get_local_public_key() };
    if request.src_port == 0 {
        let local_addr_clone = local_addr;
        let des_ip_clone = request.des_ip.clone();
        tokio::spawn(async move {
            forward_connect_request(
                &des_ip_clone,
                request.des_port,
                &local_addr_clone,
                &local_public_key,
            )
            .await;
        });

        let is_chain_empty = states.blockchain.lock().unwrap().is_chain_empty();
        let last_index = if is_chain_empty {
            None
        } else {
            Some(states.blockchain.lock().unwrap().last_index())
        };
        tokio::spawn(async move {
            if let Err(e) = send_sync_request(local_addr_clone, des_addr, None, last_index).await {
                log::error!("Failed to request full blockchain: {}", e);
            }
        });
    } else if des_addr == local_addr {
        let mut nodes = states.nodes.lock().unwrap();
        if !nodes.exists(src_addr) {
            if !request.is_response {
                let src_ip_clone = request.src_ip.clone();
                tokio::spawn(async move {
                    connect_responding(
                        &src_ip_clone,
                        request.src_port,
                        &local_addr,
                        &local_public_key,
                    )
                    .await;
                });
            }
            if !request.is_broadcast {
                let nodes_list = nodes.get_nodes_addr();
                let public_key_clone = request.public_key.clone();
                tokio::spawn(async move {
                    connect_broadcast(
                        &request.src_ip,
                        request.src_port,
                        &public_key_clone,
                        nodes_list,
                    )
                    .await;
                });
                log::info!("Broadcasted new node to other nodes");
            }
            nodes.add_node(src_addr, request.public_key.clone());
            log::info!("Node {:?} added", src_addr);
        } else {
            log::info!("Node {:?} already exists", src_addr);
        }
    } else {
        log::info!("Misrouted connect request from {:?}", src_addr);
    }
    log::debug!(
        "Current nodes: {:?}",
        states.nodes.lock().unwrap().get_nodes_addr()
    );
    Json(serde_json::json!({"status":"connect request received"}))
}

pub async fn sync_handler(
    State(states): State<AppStates>,
    Json(request): Json<SyncRequest>,
) -> impl IntoResponse {
    log::info!("Sync Request received from {:?}", request.src_addr);
    let local_addr = { states.nodes.lock().unwrap().get_local_addr() };
    let mut blockchain = { states.blockchain.lock().unwrap() };

    match (blockchain.is_chain_empty(), request.last_block_index) {
        (true, None) => {
            Json(serde_json::json!({"status":"Two empty blockchains, add genesis block first!"}))
        }
        (true, Some(_)) => {
            if let Some(remote_blockchain) = request.blockchain {
                blockchain.replace_blockchain(&remote_blockchain);
                Json(serde_json::json!({"status":"Synced"}))
            } else {
                let local_addr_clone = local_addr;
                tokio::spawn(async move {
                    if let Err(e) =
                        send_sync_request(local_addr_clone, request.src_addr, None, None).await
                    {
                        log::error!("Failed to request full blockchain: {}", e);
                    }
                });
                Json(serde_json::json!({"status":"Requested full blockchain"}))
            }
        }
        (false, None) => {
            let local_addr_clone = local_addr;
            let blockchain_clone = blockchain.clone();
            let last_index = blockchain.last_index();
            tokio::spawn(async move {
                if let Err(e) = send_sync_request(
                    local_addr_clone,
                    request.src_addr,
                    Some(blockchain_clone),
                    Some(last_index),
                )
                .await
                {
                    log::error!("Failed to send local blockchain: {}", e);
                }
            });
            Json(serde_json::json!({"status":"Sent local blockchain"}))
        }
        (false, Some(remote_index)) => {
            if remote_index > blockchain.last_index() {
                if let Some(remote_blockchain) = request.blockchain {
                    blockchain.replace_blockchain(&remote_blockchain);
                    Json(serde_json::json!({"status":"Synced"}))
                } else {
                    let local_addr_clone = local_addr;
                    tokio::spawn(async move {
                        if let Err(e) =
                            send_sync_request(local_addr_clone, request.src_addr, None, None).await
                        {
                            log::error!("Failed to request full blockchain: {}", e);
                        }
                    });
                    Json(serde_json::json!({"status":"Requested full blockchain"}))
                }
            } else if remote_index < blockchain.last_index() {
                let local_addr_clone = local_addr;
                let blockchain_clone = blockchain.clone();
                let last_index = blockchain.last_index();
                tokio::spawn(async move {
                    if let Err(e) = send_sync_request(
                        local_addr_clone,
                        request.src_addr,
                        Some(blockchain_clone),
                        Some(last_index),
                    )
                    .await
                    {
                        log::error!("Failed to send local blockchain: {}", e);
                    }
                });
                Json(serde_json::json!({"status":"Sent local blockchain"}))
            } else {
                Json(serde_json::json!({"status":"Same Length"}))
            }
        }
    }
}

pub async fn heartbeat_handler(
    State(states): State<AppStates>,
    Json(heartbeat): Json<Heartbeat>,
) -> impl IntoResponse {
    let addr = heartbeat.addr;
    let public_key = heartbeat.public_key;

    states.nodes.lock().unwrap().update_node(addr, public_key);

    let is_chain_empty = states.blockchain.lock().unwrap().is_chain_empty();
    let last_index = if is_chain_empty {
        None
    } else {
        Some(states.blockchain.lock().unwrap().last_index())
    };

    if last_index != heartbeat.last_index {
        let local_addr = states.nodes.lock().unwrap().get_local_addr();
        tokio::spawn(async move {
            if let Err(e) = send_sync_request(local_addr, addr, None, last_index).await {
                log::error!("Failed to request full blockchain: {}", e);
            }
        });
        log::info!("Sent sync request to {:?}", addr);
    }

    log::info!("Received heartbeat from {:?}", addr);
    log::debug!(
        "Current nodes: {:?}",
        states.nodes.lock().unwrap().get_nodes_addr()
    );

    Json(serde_json::json!({"status":"received"}))
}

pub async fn heartbeat(
    node_manager: Arc<Mutex<NodeManager>>,
    blockchain: Arc<Mutex<Blockchain>>,
    local_addr: SocketAddr,
    local_public_key: String,
) {
    let mut interval = interval(Duration::from_secs(5));
    loop {
        interval.tick().await;

        // Remove expired nodes
        node_manager
            .lock()
            .unwrap()
            .remove_expired_nodes(Duration::from_secs(10));

        // Get current blockchain state
        let is_chain_empty = blockchain.lock().unwrap().is_chain_empty();
        let last_index = if is_chain_empty {
            None
        } else {
            Some(blockchain.lock().unwrap().last_index())
        };

        // Send heartbeat to all known nodes
        let nodes = node_manager
            .lock()
            .unwrap()
            .get_nodes_addr()
            .iter()
            .skip(1)
            .cloned()
            .collect::<Vec<_>>();
        for node_addr in nodes {
            if node_addr != local_addr {
                if let Err(e) = reqwest::Client::new()
                    .post(format!("http://{}/heartbeat", node_addr))
                    .json(&Heartbeat {
                        addr: local_addr,
                        public_key: local_public_key.clone(),
                        last_index,
                    })
                    .send()
                    .await
                {
                    log::warn!("Failed to send heartbeat to {}: {}", node_addr, e);
                }
            }
        }
    }
}

pub async fn genesis_block_handler(State(states): State<AppStates>) -> impl IntoResponse {
    let mut blockchain = states.blockchain.lock().unwrap();
    if !blockchain.is_chain_empty() {
        return Json(serde_json::json!({"status":"Genesis block already exists"}));
    }
    let genesis_block = Block::genesis();
    blockchain.add_genesis_block(genesis_block.clone());

    let nodes = states.nodes.lock().unwrap().get_nodes_addr();
    tokio::spawn(async move {
        mining::broadcast_new_block(genesis_block, String::from(""), nodes, true).await;
    });

    log::info!("Genesis block added: {:?}", blockchain.last_block());
    Json(serde_json::json!({"status":"Genesis block added"}))
}

pub async fn faucet_handler(
    State(states): State<AppStates>,
    Json(request): Json<RequestWithKey>,
) -> impl IntoResponse {
    match public_key_from_string(&request.public_key) {
        Ok(receiver_public_key) => {
            let receiver = format!("0x{}", hex::encode(receiver_public_key.serialize()));
            let tx = Transaction::coinbase_reward(&receiver);

            if let Err(e) = states
                .blockchain
                .lock()
                .unwrap()
                .add_pending_transaction(tx.clone())
            {
                return Json(serde_json::json!({"status":e}));
            }

            let nodes = states.nodes.lock().unwrap().get_nodes_addr();
            tokio::spawn(async move {
                if let Err(e) = transaction::broadcast_new_transaction(&tx, &nodes).await {
                    log::error!("Error broadcasting transaction: {:?}", e);
                }
            });

            log::info!("Sent $10 to {}", receiver);
            Json(serde_json::json!({"status":format!("sent $10 to {}", receiver)}))
        }
        Err(e) => Json(serde_json::json!({"status":e})),
    }
}

pub async fn balance_handler(
    State(states): State<AppStates>,
    Json(request): Json<RequestWithKey>,
) -> impl IntoResponse {
    match public_key_from_string(&request.public_key) {
        Ok(public_key) => {
            let addr = format!("0x{}", hex::encode(public_key.serialize()));
            let balance = states.blockchain.lock().unwrap().balance(&addr);
            log::info!("Balance of {}: {}({})", addr, balance.0, balance.1);
            Json(serde_json::json!({
                "fixed_balance": balance.0,
                "pending_balance": balance.1
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": e,
            "fixed_balance": 0.0,
            "pending_balance": 0.0
        })),
    }
}

pub async fn mine_handler(
    State(states): State<AppStates>,
    Json(mining_state): Json<MiningStateRequest>,
) -> impl IntoResponse {
    let state_control = mining_state.state_control;
    if state_control.as_deref() == Some("OFF") {
        states.mining_state.store(false, Ordering::SeqCst);
        return Json(serde_json::json!({"status":"Mining Stopped", "state":"OFF"}));
    }
    if states.blockchain.lock().unwrap().is_chain_empty() {
        return Json(serde_json::json!({"status":"Add Genesis Block First!", "state":"OFF"}));
    }
    if states.mining_state.load(Ordering::SeqCst) {
        states.mining_state.store(false, Ordering::SeqCst);
        interval(Duration::from_secs(1)).tick().await; // This might be unnecessary in production
        log::info!("Mining in progress, Stop and Restart Mining with new request");
    }
    states.mining_state.store(true, Ordering::SeqCst);
    tokio::spawn(async move {
        mining::mine_block(states.clone()).await;
    });

    Json(serde_json::json!({"status":"Mining started", "state":"ON"}))
}

pub async fn new_block_handler(
    State(states): State<AppStates>,
    Json(request): Json<NewBlockRequest>,
) -> impl IntoResponse {
    if request.is_genesis {
        let mut blockchain = states.blockchain.lock().unwrap();
        blockchain.add_genesis_block(request.new_block.clone());
        log::info!("Genesis block added: {:?}", blockchain.last_block());
        return Json(serde_json::json!({"status":"Genesis block added"}));
    }

    let new_block = &request.new_block;
    let last_hash = &request.last_hash;

    let mut blockchain = states.blockchain.lock().unwrap();
    let nodes_count = states.nodes.lock().unwrap().get_nodes_addr().len();

    let response = if new_block.index() - 1 == blockchain.last_index() {
        if last_hash == &blockchain.last_hash() {
            if mining::verify_answer(last_hash, nodes_count, new_block.nonce()) {
                blockchain.add_block(new_block.clone());
                log::info!("New block added, Index: {}", new_block.index());
                NewBlockResponse::Success
            } else {
                log::warn!("Invalid Nonce Answer");
                NewBlockResponse::NonceError
            }
        } else {
            log::warn!("Last Hash Value Mismatch");
            NewBlockResponse::HashError
        }
    } else {
        log::warn!("Index Value Mismatch");
        NewBlockResponse::SyncRequest
    };

    match response {
        NewBlockResponse::Success => Json(serde_json::json!({"status":"New block added"})),
        NewBlockResponse::SyncRequest => Json(serde_json::json!({"status":"Sync Request"})),
        NewBlockResponse::NonceError => Json(serde_json::json!({"status":"Invalid Nonce Answer"})),
        NewBlockResponse::HashError => {
            Json(serde_json::json!({"status":"Last Hash Value Mismatch"}))
        }
    }
}

pub async fn generate_key_pair() -> impl IntoResponse {
    let (private_key, public_key) = generate_keypair(&mut rand::thread_rng());
    Json(KeyPair {
        private_key: hex::encode(private_key.secret_bytes()),
        public_key: hex::encode(public_key.serialize()),
    })
}
async fn forward_connect_request(
    des_ip: &str,
    des_port: u16,
    local_addr: &SocketAddr,
    local_public_key: &str,
) {
    let client = reqwest::Client::new();
    match client
        .post(format!("http://{}:{}/connect", des_ip, des_port))
        .json(&ConnectRequest {
            des_ip: des_ip.to_string(),
            des_port,
            src_ip: local_addr.ip().to_string(),
            src_port: local_addr.port(),
            public_key: local_public_key.to_string(),
            is_broadcast: false,
            is_response: false,
        })
        .send()
        .await
    {
        Ok(_) => log::info!("Forwarded post request to {}:{}", des_ip, des_port),
        Err(e) => log::error!("Error forwarding post request: {:?}", e),
    }
}

async fn connect_responding(
    src_ip: &str,
    src_port: u16,
    local_addr: &SocketAddr,
    local_public_key: &str,
) {
    let client = reqwest::Client::new();
    match client
        .post(format!("http://{}:{}/connect", src_ip, src_port))
        .json(&ConnectRequest {
            des_ip: src_ip.to_string(),
            des_port: src_port,
            src_ip: local_addr.ip().to_string(),
            src_port: local_addr.port(),
            public_key: local_public_key.to_string(),
            is_broadcast: false,
            is_response: true,
        })
        .send()
        .await
    {
        Ok(_) => log::info!("Responding to post request from {}:{}", src_ip, src_port),
        Err(e) => log::error!("Error responding to post request: {:?}", e),
    }
}

async fn connect_broadcast(
    new_node_ip: &str,
    new_node_port: u16,
    public_key: &str,
    nodes: Vec<SocketAddr>,
) {
    let client = reqwest::Client::new();
    for node_addr in nodes.iter().skip(1) {
        match client
            .post(format!("http://{}/connect", node_addr))
            .json(&ConnectRequest {
                des_ip: node_addr.ip().to_string(),
                des_port: node_addr.port(),
                src_ip: new_node_ip.to_string(),
                src_port: new_node_port,
                public_key: public_key.to_string(),
                is_broadcast: true,
                is_response: false,
            })
            .send()
            .await
        {
            Ok(_) => log::info!("Broadcasted new node to {:?}", node_addr),
            Err(e) => log::error!("Error broadcasting new node to {:?}: {:?}", node_addr, e),
        }
    }
}

pub async fn miner_keys(State(states): State<AppStates>) -> impl IntoResponse {
    let nodes = states.nodes.lock().unwrap();
    let (private_key, public_key) = nodes.get_local_keys();
    Json(KeyPair {
        private_key: private_key.unwrap_or_default().to_string(),
        public_key: public_key.unwrap_or_default().to_string(),
    })
}

pub async fn blockchain_info(State(states): State<AppStates>) -> impl IntoResponse {
    let blockchain = states.blockchain.lock().unwrap();
    let nodes = states.nodes.lock().unwrap().get_nodes();
    Json(serde_json::json!({
        "nodes": nodes,
        "blockchain": blockchain.chain(),
        "pending_transactions": blockchain.pending_transactions(),
    }))
}

async fn send_sync_request(
    local_addr: SocketAddr,
    target_addr: SocketAddr,
    blockchain: Option<Blockchain>,
    last_index: Option<u64>,
) -> Result<(), String> {
    let client = reqwest::Client::new();
    match client
        .post(format!("http://{}/sync", target_addr))
        .json(&SyncRequest {
            blockchain,
            last_block_index: last_index,
            src_addr: local_addr,
        })
        .send()
        .await
    {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Network error: {}", e)),
    }
}
