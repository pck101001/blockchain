use crate::utils::{ConnectRequest, Heartbeat};
use crate::{blockchain::Blockchain, node::NodeManager, transaction::Transaction};
use crate::{node, transaction};
use axum::{extract::State, response::IntoResponse, Json};
use reqwest;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::time::{interval, Duration};

pub async fn transaction_submit_handler(
    State((blockchain, nodes)): State<(Arc<Mutex<Blockchain>>, Arc<Mutex<NodeManager>>)>,
    Json(transaction): Json<Transaction>,
) -> impl IntoResponse {
    println!("Submitted transaction: {:?}", transaction);
    let mut blockchain = blockchain.lock().unwrap();
    blockchain.add_pending_transaction(transaction.clone());
    let nodes = nodes
        .lock()
        .unwrap()
        .get_nodes()
        .iter()
        .skip(1)
        .cloned()
        .collect::<Vec<_>>();
    let transaction_for_flooding = Arc::new(transaction);
    for node in nodes {
        let client = reqwest::Client::new();
        let transaction_clone = Arc::clone(&transaction_for_flooding);
        tokio::spawn(async move {
            let _ = client
                .post(format!("http://{}/transaction/flooding", node))
                .json(&*transaction_clone)
                .send()
                .await;
        });
        println!("Flooding transaction to {:?}", node);
    }

    Json(serde_json::json!({"status":"pending transaction added"}))
}

pub async fn transaction_flooding_handler(
    State((blockchain, nodes)): State<(Arc<Mutex<Blockchain>>, Arc<Mutex<NodeManager>>)>,
    Json(transaction): Json<Transaction>,
) -> impl IntoResponse {
    let mut blockchain = blockchain.lock().unwrap();
    blockchain.add_pending_transaction(transaction.clone());
    println!("Flooding transaction added: {:?}", transaction);
    Json(serde_json::json!({"status":"flooding transaction added"}))
}

pub async fn connect_handler(
    State((_blockchain, nodes)): State<(Arc<Mutex<Blockchain>>, Arc<Mutex<NodeManager>>)>,
    Json(connect_request): Json<ConnectRequest>,
) -> impl IntoResponse {
    let des_addr = SocketAddr::new(
        connect_request.des_ip.parse().unwrap(),
        connect_request.des_port,
    );
    let src_addr = SocketAddr::new(
        connect_request.src_ip.parse().unwrap(),
        connect_request.src_port,
    );
    println!(
        "New POST Request received: src: {:?}, des: {:?}",
        src_addr, des_addr
    );
    let local_addr = nodes.lock().unwrap().get_local_addr();
    if connect_request.src_port == 0 {
        let forward_post = reqwest::Client::new();
        let res = forward_post
            .post(format!(
                "http://{}:{}/connect",
                connect_request.des_ip, connect_request.des_port
            ))
            .json(&ConnectRequest {
                des_ip: connect_request.des_ip.clone(),
                des_port: connect_request.des_port,
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
        let exists = nodes.lock().unwrap().exists(src_addr);
        if !exists {
            nodes.lock().unwrap().add_node(src_addr);
            let response_post = reqwest::Client::new();
            let res = response_post
                .post(format!(
                    "http://{}:{}/connect",
                    connect_request.src_ip, connect_request.src_port
                ))
                .json(&ConnectRequest {
                    des_ip: connect_request.src_ip.clone(),
                    des_port: connect_request.src_port,
                    src_ip: local_addr.ip().to_string(),
                    src_port: local_addr.port(),
                })
                .send()
                .await;
            match res {
                Ok(_) => println!("responding to post request from {:?}", src_addr),
                Err(e) => println!("error responding to post request: {:?}", e),
            }
            let nodes = nodes
                .lock()
                .unwrap()
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
    println!("Current nodes: {:?}", nodes.lock().unwrap().get_nodes());
    Json(serde_json::json!({"status":"received connect request"}))
}

pub async fn heartbeat_handler(
    State((_blockchain, nodes)): State<(Arc<Mutex<Blockchain>>, Arc<Mutex<NodeManager>>)>,
    Json(heartbeat): Json<Heartbeat>,
) -> impl IntoResponse {
    let addr = heartbeat.addr;
    nodes.lock().unwrap().update_node(addr);
    println!("Received heartbeat from {:?}", addr);
    println!("Current nodes: {:?}", nodes.lock().unwrap().get_nodes());
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
