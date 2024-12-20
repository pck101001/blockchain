use axum::{
    response::Html,
    routing::{get, post},
    Router,
};
use axum_server::Server;
use std::collections::HashMap;
use std::env;
use std::process;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tower_http::services::ServeDir;

mod block;
mod blockchain;
mod mining;
mod node;
mod server;
mod transaction;
mod utils;

#[tokio::main]
async fn main() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .init();
    let local_addr = utils::Config::new(env::args())
        .unwrap_or_else(|err| {
            eprintln!("Problem parsing arguments: {}", err);
            process::exit(1);
        })
        .addr();
    let blockchain = Arc::new(Mutex::new(blockchain::Blockchain::new()));
    let nodes = Arc::new(Mutex::new(node::NodeManager::new(&local_addr)));
    let mining_state = Arc::new(AtomicBool::new(false));
    let states = utils::AppStates {
        blockchain: blockchain.clone(),
        nodes: nodes.clone(),
        mining_state: mining_state.clone(),
    };
    let app = Router::new()
        .nest_service("/static", ServeDir::new("static"))
        .route(
            "/",
            get(|| async { Html(include_str!("../templates/index.html")) }),
        )
        .route(
            "/transaction/submit",
            post(server::transaction_submit_handler),
        )
        .route(
            "/transaction/broadcast",
            post(server::transaction_broadcast_handler),
        )
        .route("/connect", post(server::connect_handler))
        .route("/sync", post(server::sync_handler))
        .route("/heartbeat", post(server::heartbeat_handler))
        .route("/genesis_block", post(server::genesis_block_handler))
        .route("/faucet", post(server::faucet_handler))
        .route("/balance", post(server::balance_handler))
        .route("/mine", post(server::mine_handler))
        .route("/miner_keys", get(server::miner_keys))
        .route("/new_block", post(server::new_block_handler))
        .route("/generate_key_pair", get(server::generate_key_pair))
        .with_state(states);
    let local_public_key = nodes.lock().unwrap().get_local_public_key();
    tokio::spawn(server::heartbeat(
        nodes.clone(),
        local_addr,
        local_public_key,
    ));
    Server::bind(local_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
