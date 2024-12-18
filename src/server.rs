use crate::block;
use crate::utils::{
    is_key_match, private_key_from_string, public_key_from_string, AppStates, ConnectRequest,
    Heartbeat, KeyPair, NewBlockRequest, NewBlockResponse, RequestWithKey, SyncRequest,
    TransactionRequest,
};
use crate::{
    block::Block,
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
            } else {
                println!("start initial sync with {:?}", src_addr);
                // let blockchain_clone = { states.blockchain.lock().unwrap().clone() };
                // let nodes_clone = { states.nodes.lock().unwrap().get_nodes() };

                // tokio::spawn(async move {
                //     let client = reqwest::Client::new();
                //     let res = client
                //         .post(format!("http://{}/sync", src_addr))
                //         .json(&SyncRequest {
                //             blockchain: Some(blockchain_clone),
                //             nodes: Some(nodes_clone),
                //             is_response: false,
                //             src_addr: local_addr,
                //         })
                //         .send()
                //         .await;
                //     match res {
                //         Ok(_) => println!("sync request sent to {:?}", src_addr),
                //         Err(e) => println!("error sending sync request: {:?}", e),
                //     }
                // });
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
    let mut response = SyncRequest {
        blockchain: Some(states.blockchain.lock().unwrap().clone()),
        nodes: Some(states.nodes.lock().unwrap().get_nodes()),
        is_response: true,
        src_addr: { states.nodes.lock().unwrap().get_local_addr() },
    };
    if request.blockchain.is_some() {
        let last_index = { states.blockchain.lock().unwrap().last_index() };
        println!("last index: {:?}", last_index);
        println!(
            "received blockchain last index: {:?}",
            request.blockchain.as_ref().unwrap().last_index()
        );
        if request.blockchain.as_ref().unwrap().last_index() > last_index {
            let mut blockchain = states.blockchain.lock().unwrap();
            *blockchain = request.blockchain.unwrap();
            response.blockchain = Option::None;
        }
    }
    if request.nodes.is_some() {
        let mut nodes_manager = states.nodes.lock().unwrap();
        println!("received nodes: {:?}", request.nodes.as_ref().unwrap());
        println!("current nodes: {:?}", nodes_manager.get_nodes_addr());
        for node in request.nodes.as_ref().unwrap() {
            nodes_manager.add_node_with_node(node.clone());
        }
    }
    if !request.is_response {
        println!("sending sync response to {:?}", request.src_addr);
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let res = client
                .post(format!("http://{}/sync", request.src_addr))
                .json(&response)
                .send()
                .await;
            match res {
                Ok(_) => println!("sync response sent to {:?}", request.src_addr),
                Err(e) => println!("error sending sync response: {:?}", e),
            }
        });
    }
    Json(serde_json::json!({"status":"sync request received"}))
}

pub async fn heartbeat_handler(
    State(states): State<AppStates>,
    Json(heartbeat): Json<Heartbeat>,
) -> impl IntoResponse {
    let addr = heartbeat.addr;
    let mut nodes = states.nodes.lock().unwrap();
    nodes.update_node(addr, heartbeat.public_key.clone());
    println!("Received heartbeat from {:?}", addr);
    println!("Current nodes: {:?}", nodes.get_nodes_addr());
    Json(serde_json::json!({"status":"received"}))
}

pub async fn heartbeat(
    node_manager: Arc<Mutex<NodeManager>>,
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
        for node_addr in nodes {
            if node_addr != local_addr {
                let client = reqwest::Client::new();
                let _ = client
                    .post(format!("http://{}/heartbeat", node_addr))
                    .json(&Heartbeat {
                        addr: local_addr,
                        public_key: local_public_key.clone(),
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
    let tx = Transaction::coin_base_reward(&receiver);
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
        Err(e) => return Json(serde_json::json!({"status":e})),
    };
    let addr = format!("0x{}", hex::encode(public_key.serialize()));
    let balance = states.blockchain.lock().unwrap().balance(&addr);
    println!("Balance of {}: {}({})", addr, balance.0, balance.1);
    Json(serde_json::json!({
        "fixed_balance": balance.0,
        "pending_balance": balance.1
    }))
}

pub async fn mine_handler(State(states): State<AppStates>) -> impl IntoResponse {
    if states.blockchain.lock().unwrap().is_chain_empty() {
        return Json(serde_json::json!({"status":"Add Genesis Block First!"}));
    }
    if states.mining_state.load(Ordering::SeqCst) {
        states.mining_state.store(false, Ordering::SeqCst);
        interval(Duration::from_secs(1)).tick().await;
        println!("Mining in progress, Stop and Restart Mining with new request");
    }
    let last_hash = { states.blockchain.lock().unwrap().last_hash() };
    states.mining_state.store(true, Ordering::SeqCst);
    tokio::spawn(async move {
        mining::mine_block(states.clone(), last_hash.clone()).await;
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
    if states.mining_state.load(Ordering::SeqCst) {
        states.mining_state.store(false, Ordering::SeqCst);
        println!("Mining Stopped");
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
                println!("New block added: {:?}", new_block);
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
        return Err("invalid sender key pair".to_string());
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
        return Err("invalid transaction".to_string());
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

// async fn process_votes(states: Arc<AppStates>) {
//     let timeout_duration = Duration::from_secs(10);
//     loop {
//         let mut votes = states.votes.lock().unwrap();
//         let now = SystemTime::now();
//         votes.retain()
//     }
// }
