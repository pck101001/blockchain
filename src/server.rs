use crate::utils::{
    is_key_match, private_key_from_string, public_key_from_string, AppStates, ConnectRequest,
    Heartbeat, KeyPair, NewBlockRequest, NewBlockResponse, RequestWithKey, TransactionRequest,
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
    let sender_private_key = match private_key_from_string(&request.sender_private_key) {
        Ok(private_key) => private_key,
        Err(e) => return Json(serde_json::json!({"status":e})),
    };
    let sender_public_key = match public_key_from_string(&request.sender_public_key) {
        Ok(public_key) => public_key,
        Err(e) => return Json(serde_json::json!({"status":e})),
    };
    let receiver_public_key = match public_key_from_string(&request.receiver_public_key) {
        Ok(public_key) => public_key,
        Err(e) => return Json(serde_json::json!({"status":e})),
    };

    if is_key_match(&sender_private_key, &sender_public_key).is_err() {
        return Json(serde_json::json!({"status":"invalid sender key pair"}));
    }

    let raw_transaction = RawTransaction {
        sender: format!("0x{}", hex::encode(sender_public_key.serialize())),
        receiver: format!("0x{}", hex::encode(receiver_public_key.serialize())),
        amount: request.amount,
        time: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
        is_coinbase: false,
    };
    let transaction = Transaction::new(raw_transaction.clone(), &sender_private_key);
    if transaction.verify().is_err() {
        return Json(serde_json::json!({"status":"invalid transaction"}));
    }
    let mut blockchain = { states.blockchain.lock().unwrap() };
    blockchain.add_pending_transaction(transaction.clone());
    let nodes = { states.nodes.lock().unwrap().get_nodes() };
    let transaction_clone = transaction.clone();
    tokio::spawn(async move {
        transaction::broadcast_new_transaction(transaction.clone(), nodes).await;
    });
    println!("Transaction added: {:?}", transaction_clone);

    Json(serde_json::json!({"status":"pending transaction added"}))
}

pub async fn transaction_flooding_handler(
    State(states): State<AppStates>,
    Json(transaction): Json<Transaction>,
) -> impl IntoResponse {
    if transaction.verify().is_err() {
        return Json(serde_json::json!({"status":"invalid transaction"}));
    }
    let mut blockchain = states.blockchain.lock().unwrap();
    blockchain.add_pending_transaction(transaction.clone());
    println!("Flooding transaction added: {:?}", transaction);
    Json(serde_json::json!({"status":"flooding transaction added"}))
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
    if request.src_port == 0 {
        let forward_post = reqwest::Client::new();
        let res = forward_post
            .post(format!(
                "http://{}:{}/connect",
                request.des_ip, request.des_port
            ))
            .json(&ConnectRequest {
                des_ip: request.des_ip.clone(),
                des_port: request.des_port,
                src_ip: local_addr.ip().to_string(),
                src_port: local_addr.port(),
            })
            .send()
            .await;
        match res {
            Ok(_) => println!("forwarding post request to {:?}", des_addr),
            Err(e) => println!("error forwarding post request: {:?}", e),
        }
    } else if des_addr == local_addr {
        let mut nodes = states.nodes.lock().unwrap();
        let exists = nodes.exists(src_addr);
        if !exists {
            nodes.add_node(src_addr);

            tokio::spawn(async move {
                let response_post = reqwest::Client::new();
                let res = response_post
                    .post(format!(
                        "http://{}:{}/connect",
                        request.src_ip, request.src_port
                    ))
                    .json(&ConnectRequest {
                        des_ip: request.src_ip.clone(),
                        des_port: request.src_port,
                        src_ip: local_addr.ip().to_string(),
                        src_port: local_addr.port(),
                    })
                    .send()
                    .await;
                match res {
                    Ok(_) => println!("responding to post request from {:?}", src_addr),
                    Err(e) => println!("error responding to post request: {:?}", e),
                }
            });

            let nodes = nodes
                .get_nodes()
                .iter()
                .skip(1)
                .cloned()
                .collect::<Vec<_>>();
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                for node_addr in nodes {
                    if node_addr != local_addr && node_addr != src_addr {
                        let _ = client
                            .post(format!("http://{}/connect", node_addr))
                            .json(&ConnectRequest {
                                des_ip: node_addr.ip().to_string(),
                                des_port: node_addr.port(),
                                src_ip: src_addr.ip().to_string(),
                                src_port: src_addr.port(),
                            })
                            .send()
                            .await;
                    }
                }
            });
            println!("Flooding connect request to other nodes");
        } else {
            println!("node {:?} already exists", src_addr);
        }
    } else {
        println!("misrouted post request from {:?}", src_addr);
    }
    println!(
        "Current nodes: {:?}",
        states.nodes.lock().unwrap().get_nodes()
    );
    Json(serde_json::json!({"status":"received connect request"}))
}

pub async fn heartbeat_handler(
    State(states): State<AppStates>,
    Json(heartbeat): Json<Heartbeat>,
) -> impl IntoResponse {
    let addr = heartbeat.addr;
    let mut nodes = states.nodes.lock().unwrap();
    nodes.update_node(addr);
    println!("Received heartbeat from {:?}", addr);
    println!("Current nodes: {:?}", nodes.get_nodes());
    Json(serde_json::json!({"status":"received"}))
}

pub async fn heartbeat(node_manager: Arc<Mutex<NodeManager>>, local_addr: SocketAddr) {
    let mut interval = interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        node_manager
            .lock()
            .unwrap()
            .remove_expired_nodes(Duration::from_secs(10));
        let nodes = node_manager.lock().unwrap().get_nodes();
        for node_addr in nodes {
            if node_addr != local_addr {
                let client = reqwest::Client::new();
                let _ = client
                    .post(format!("http://{}/heartbeat", node_addr))
                    .json(&Heartbeat { addr: local_addr })
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
    let nodes = { states.nodes.lock().unwrap().get_nodes() };
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
    states
        .blockchain
        .lock()
        .unwrap()
        .add_pending_transaction(tx.clone());
    let nodes = { states.nodes.lock().unwrap().get_nodes() };
    tokio::spawn(async move {
        transaction::broadcast_new_transaction(tx.clone(), nodes).await;
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
    println!("Balance of {}: {}", addr, balance);
    Json(serde_json::json!({
        "balance": balance,
    }))
}

pub async fn mine_handler(
    State(states): State<AppStates>,
    Json(request): Json<RequestWithKey>,
) -> impl IntoResponse {
    if states.mining_state.load(Ordering::SeqCst) {
        states.mining_state.store(false, Ordering::SeqCst);
        interval(Duration::from_secs(1)).tick().await;
        println!("Mining in progress, Stop and Restart Mining with new request");
    }
    let miner = request.public_key;
    let last_hash = { states.blockchain.lock().unwrap().last_hash() };
    states.mining_state.store(true, Ordering::SeqCst);
    tokio::spawn(async move {
        mining::mine_block(states.clone(), last_hash.clone(), miner.clone()).await;
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
    let nodes_count = { states.nodes.lock().unwrap().get_nodes().len() };

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
