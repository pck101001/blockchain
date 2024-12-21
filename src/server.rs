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
    println!("Submitted transaction: {:?}", request);
    let transaction = match pack_transaction(request) {
        Ok(transaction) => transaction,
        Err(e) => {
            println!("Error: {:?}", e);
            return Json(serde_json::json!({"status":e}));
        }
    };
    let mut blockchain = { states.blockchain.lock().unwrap() };
    match blockchain.add_pending_transaction(transaction.clone()) {
        Ok(_) => {}
        Err(e) => {
            println!("Error:{:?}", e);
            return Json(serde_json::json!({"status":e}));
        }
    }
    let nodes = { states.nodes.lock().unwrap().get_nodes_addr() };
    let transaction_clone = transaction.clone();
    tokio::spawn(async move {
        if let Err(e) = transaction::broadcast_new_transaction(transaction.clone(), nodes).await {
            log::error!("Error broadcasting transaction: {:?}", e);
        }
    });
    println!("Transaction added: {:?}", transaction_clone);
    Json(serde_json::json!({"status":"Transaction submitted"}))
}

pub async fn transaction_broadcast_handler(
    State(states): State<AppStates>,
    Json(transaction): Json<Transaction>,
) -> impl IntoResponse {
    if let Err(e) = transaction.verify() {
        return Json(serde_json::json!({"status":e.to_string()}));
    }
    let mut blockchain = states.blockchain.lock().unwrap();
    if let Err(e) = blockchain.add_pending_transaction(transaction.clone()) {
        return Json(serde_json::json!({"status":e}));
    }
    println!("broadcast transaction added: {:?}", transaction);
    Json(serde_json::json!({"status":"broadcast transaction added"}))
}

pub async fn connect_handler(
    State(states): State<AppStates>,
    Json(request): Json<ConnectRequest>,
) -> impl IntoResponse {
    let des_addr = SocketAddr::new(request.des_ip.parse().unwrap(), request.des_port);
    let src_addr = SocketAddr::new(request.src_ip.parse().unwrap(), request.src_port);
    println!(
        "New POST Request received: src: {:?}, des: {:?}",
        src_addr, des_addr
    );
    let local_addr = { states.nodes.lock().unwrap().get_local_addr() };
    let local_public_key = { states.nodes.lock().unwrap().get_local_public_key() };
    if request.src_port == 0 {
        tokio::spawn(async move {
            forward_connect_request(
                &request.des_ip,
                request.des_port,
                &local_addr,
                &local_public_key,
            )
            .await;
        });
        let local_addr_clone = local_addr.clone();
        let is_chain_empty = { states.blockchain.lock().unwrap().is_chain_empty() };
        let last_index = match is_chain_empty {
            true => None,
            false => Some(states.blockchain.lock().unwrap().last_index()),
        };
        tokio::spawn(async move {
            if let Err(e) = send_sync_request(local_addr_clone, des_addr, None, last_index).await {
                println!("Failed to request full blockchain: {}", e);
            }
        });
    } else if des_addr == local_addr {
        let mut nodes = states.nodes.lock().unwrap();
        let exists = nodes.exists(src_addr);
        if !exists {
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
                let nodes = { nodes.get_nodes_addr() };
                let public_key_clone = request.public_key.clone();
                tokio::spawn(async move {
                    connect_broadcast(&request.src_ip, request.src_port, &public_key_clone, nodes)
                        .await;
                });
                println!("broadcasted new node to other nodes");
            }
            nodes.add_node(src_addr, request.public_key.clone());
            println!("node {:?} added", src_addr);
        } else {
            println!("node {:?} already exists", src_addr);
        }
    } else {
        println!("misrouted post request from {:?}", src_addr);
    }
    println!(
        "Current nodes: {:?}",
        states.nodes.lock().unwrap().get_nodes_addr()
    );
    Json(serde_json::json!({"status":"connect request received"}))
}

pub async fn sync_handler(
    State(states): State<AppStates>,
    Json(request): Json<SyncRequest>,
) -> impl IntoResponse {
    println!("Sync Request received from {:?}", request.src_addr);
    let local_addr = { states.nodes.lock().unwrap().get_local_addr() };
    let mut blockchain = { states.blockchain.lock().unwrap() };

    println!(
        "local blockchain empty: {:?},request last index: {:?}",
        blockchain.is_chain_empty(),
        request.last_block_index
    );

    match (blockchain.is_chain_empty(), request.last_block_index) {
        // 双方都没有创世块
        (true, None) => {
            Json(serde_json::json!({"status":"Two empty blockchains, add genesis block first!"}))
        }
        // 本地没有创世块，但请求方有
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
                        println!("Failed to request full blockchain: {}", e);
                    }
                });
                Json(serde_json::json!({"status":"Requested full blockchain"}))
            }
        }
        // 本地有创世块，但请求方没有
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
                    println!("Failed to send local blockchain: {}", e);
                }
            });
            Json(serde_json::json!({"status":"Sent local blockchain"}))
        }
        // 两者都存在链，进行比较
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
                            println!("Failed to request full blockchain: {}", e);
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
                        println!("Failed to send local blockchain: {}", e);
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
    {
        states
            .nodes
            .lock()
            .unwrap()
            .update_node(addr, heartbeat.public_key.clone())
    };
    let is_chain_empty = { states.blockchain.lock().unwrap().is_chain_empty() };
    let last_index;
    match is_chain_empty {
        true => last_index = Option::None,
        false => last_index = Some(states.blockchain.lock().unwrap().last_index()),
    }
    if last_index != heartbeat.last_index {
        let local_addr = { states.nodes.lock().unwrap().get_local_addr() };
        tokio::spawn(async move {
            if let Err(e) = send_sync_request(local_addr, addr, None, last_index).await {
                println!("Failed to request full blockchain: {}", e);
            }
        });
        println!("Sent sync request to {:?}", addr);
    }
    println!("Received heartbeat from {:?}", addr);
    println!(
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
        node_manager
            .lock()
            .unwrap()
            .remove_expired_nodes(Duration::from_secs(10));
        let nodes = node_manager.lock().unwrap().get_nodes_addr();
        let last_index;
        let is_chain_empty = { blockchain.lock().unwrap().is_chain_empty() };
        match is_chain_empty {
            true => last_index = Option::None,
            false => last_index = Some(blockchain.lock().unwrap().last_index()),
        }
        for node_addr in nodes {
            if node_addr != local_addr {
                let client = reqwest::Client::new();
                let _ = client
                    .post(format!("http://{}/heartbeat", node_addr))
                    .json(&Heartbeat {
                        addr: local_addr,
                        public_key: local_public_key.clone(),
                        last_index,
                    })
                    .send()
                    .await;
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
    let nodes = { states.nodes.lock().unwrap().get_nodes_addr() };
    blockchain.add_genesis_block(genesis_block.clone());
    tokio::spawn(async move {
        mining::broadcast_new_block(genesis_block.clone(), String::from(""), nodes, true).await;
    });

    println!("Genesis block added: {:?}", blockchain.last_block());
    Json(serde_json::json!({"status":"Genesis block added"}))
}

pub async fn faucet_handler(
    State(states): State<AppStates>,
    Json(request): Json<RequestWithKey>,
) -> impl IntoResponse {
    let receiver_public_key = match public_key_from_string(&request.public_key) {
        Ok(public_key) => public_key,
        Err(e) => return Json(serde_json::json!({"status":e})),
    };
    let receiver = format!("0x{}", hex::encode(receiver_public_key.serialize()));
    let tx = Transaction::coinbase_reward(&receiver);
    println!("Sent $10 to {}\n tx:{:?}", receiver, tx);
    if let Err(e) = states
        .blockchain
        .lock()
        .unwrap()
        .add_pending_transaction(tx.clone())
    {
        return Json(serde_json::json!({"status":e}));
    }
    let nodes = { states.nodes.lock().unwrap().get_nodes_addr() };
    tokio::spawn(async move {
        if let Err(e) = transaction::broadcast_new_transaction(tx.clone(), nodes).await {
            log::error!("Error broadcasting transaction: {:?}", e);
        }
    });
    Json(serde_json::json!({"status":format!("sent $10 to {}",receiver)}))
}

pub async fn balance_handler(
    State(states): State<AppStates>,
    Json(request): Json<RequestWithKey>,
) -> impl IntoResponse {
    let public_key = match public_key_from_string(&request.public_key) {
        Ok(public_key) => public_key,
        Err(e) => {
            return Json(serde_json::json!({"status":e, "fixed_balance": 0, "pending_balance": 0}))
        }
    };
    let addr = format!("0x{}", hex::encode(public_key.serialize()));
    let balance = states.blockchain.lock().unwrap().balance(&addr);
    println!("Balance of {}: {}({})", addr, balance.0, balance.1);
    Json(serde_json::json!({
        "fixed_balance": balance.0,
        "pending_balance": balance.1
    }))
}

pub async fn mine_handler(
    State(states): State<AppStates>,
    Json(mining_state): Json<MiningStateRequest>,
) -> impl IntoResponse {
    let state_control = mining_state.state_control;
    if state_control == Some(String::from("OFF")) {
        states.mining_state.store(false, Ordering::SeqCst);
        return Json(serde_json::json!({"status":"Mining Stopped"}));
    }
    if states.blockchain.lock().unwrap().is_chain_empty() {
        return Json(serde_json::json!({"status":"Add Genesis Block First!"}));
    }
    if states.mining_state.load(Ordering::SeqCst) {
        states.mining_state.store(false, Ordering::SeqCst);
        interval(Duration::from_secs(1)).tick().await;
        println!("Mining in progress, Stop and Restart Mining with new request");
    }
    states.mining_state.store(true, Ordering::SeqCst);
    tokio::spawn(async move {
        mining::mine_block(states.clone()).await;
    });
    Json(serde_json::json!({"status":"Mining started"}))
}

pub async fn new_block_handler(
    State(states): State<AppStates>,
    Json(request): Json<NewBlockRequest>,
) -> impl IntoResponse {
    if request.is_genesis {
        let mut blockchain = states.blockchain.lock().unwrap();
        blockchain.add_genesis_block(request.new_block.clone());
        println!("Genesis block added: {:?}", blockchain.last_block());
        return Json(serde_json::json!({"status":"Genesis block added"}));
    }
    let new_block = &request.new_block;
    let last_hash = &request.last_hash;

    let mut blockchain = states.blockchain.lock().unwrap();
    let nodes_count = { states.nodes.lock().unwrap().get_nodes_addr().len() };

    let mut response = NewBlockResponse::Success;
    if new_block.index() - 1 == blockchain.last_index() {
        if *last_hash == blockchain.last_hash() {
            if mining::verify_answer(last_hash, nodes_count, new_block.nonce()) {
                blockchain.add_block(new_block.clone());
                println!("New block added, Index: {}", new_block.index());
            } else {
                println!("Invalid Nonce Answer");
                response = NewBlockResponse::NonceError;
            }
        } else {
            println!("Last Hash Value Mismatch");
            response = NewBlockResponse::HashError;
        }
    } else {
        println!("Index Value Mismatch");
        response = NewBlockResponse::SyncRequest;
    }
    match response {
        NewBlockResponse::Success => Json(serde_json::json!({"status":"New block added"})),
        NewBlockResponse::SyncRequest => Json(serde_json::json!({"status":"Need Sync Blockchain"})),
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
    let forward_post = reqwest::Client::new();
    let res = forward_post
        .post(format!("http://{}:{}/connect", des_ip, des_port))
        .json(&ConnectRequest {
            des_ip: des_ip.to_owned(),
            des_port,
            src_ip: local_addr.ip().to_string(),
            src_port: local_addr.port(),
            public_key: local_public_key.to_owned(),
            is_broadcast: false,
            is_response: false,
        })
        .send()
        .await;
    match res {
        Ok(_) => println!("forwarded post request to {:?}:{:?}", des_ip, des_port),
        Err(e) => println!("error forwarding post request: {:?}", e),
    }
}
async fn connect_responding(
    src_ip: &str,
    src_port: u16,
    local_addr: &SocketAddr,
    local_public_key: &str,
) {
    let response_post = reqwest::Client::new();
    let res = response_post
        .post(format!("http://{}:{}/connect", src_ip, src_port))
        .json(&ConnectRequest {
            des_ip: src_ip.to_owned(),
            des_port: src_port,
            src_ip: local_addr.ip().to_string(),
            src_port: local_addr.port(),
            public_key: local_public_key.to_owned(),
            is_broadcast: false,
            is_response: true,
        })
        .send()
        .await;
    match res {
        Ok(_) => println!(
            "responding to post request from {:?}:{:?}",
            src_ip, src_port
        ),
        Err(e) => println!("error responding to post request: {:?}", e),
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
        let res = client
            .post(format!("http://{}/connect", node_addr))
            .json(&ConnectRequest {
                des_ip: node_addr.ip().to_string(),
                des_port: node_addr.port(),
                src_ip: new_node_ip.to_owned(),
                src_port: new_node_port,
                public_key: public_key.to_owned(),
                is_broadcast: true,
                is_response: false,
            })
            .send()
            .await;
        match res {
            Ok(_) => println!("broadcasted new node to {:?}", node_addr),
            Err(e) => println!("error broadcasting new node: {:?}", e),
        }
    }
}
fn pack_transaction(transaction_request: TransactionRequest) -> Result<Transaction, String> {
    let sender_private_key = match private_key_from_string(&transaction_request.sender_private_key)
    {
        Ok(private_key) => private_key,
        Err(e) => return Err(e),
    };
    let sender_public_key = match public_key_from_string(&transaction_request.sender_public_key) {
        Ok(public_key) => public_key,
        Err(e) => return Err(e),
    };
    let receiver_public_key = match public_key_from_string(&transaction_request.receiver_public_key)
    {
        Ok(public_key) => public_key,
        Err(e) => return Err(e),
    };

    if is_key_match(&sender_private_key, &sender_public_key).is_err() {
        return Err("Invalid sender key pair".to_string());
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
    let transaction = Transaction::new(raw_transaction.clone(), &sender_private_key);
    if transaction.verify().is_err() {
        return Err("Invalid transaction".to_string());
    }
    Ok(transaction)
}

pub async fn miner_keys(State(states): State<AppStates>) -> impl IntoResponse {
    let (private_key, public_key) = { states.nodes.lock().unwrap().get_local_keys() };
    Json(KeyPair {
        private_key,
        public_key,
    })
}

pub async fn blockchain_info(State(states): State<AppStates>) -> impl IntoResponse {
    let blockchain = { states.blockchain.lock().unwrap() };
    let nodes = { states.nodes.lock().unwrap().get_nodes() };
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
    let res = client
        .post(format!("http://{}/sync", target_addr))
        .json(&SyncRequest {
            blockchain,
            last_block_index: last_index,
            src_addr: local_addr,
        })
        .send()
        .await;

    match res {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Network error: {}", e)),
    }
}
