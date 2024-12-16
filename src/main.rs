use axum::{
    response::Html,
    routing::{get, post},
    Router, ServiceExt,
};
use axum_server::Server;
use server::heartbeat;
use std::process;
use std::sync::{Arc, Mutex};
use std::{env, net::SocketAddr};
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
    let local_addr = utils::Config::new(env::args())
        .unwrap_or_else(|err| {
            eprintln!("Problem parsing arguments: {}", err);
            process::exit(1);
        })
        .addr();
    let blockchain = Arc::new(Mutex::new(blockchain::Blockchain::new()));
    let nodes = Arc::new(Mutex::new(node::NodeManager::new(&local_addr)));

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
            "/transaction/flooding",
            post(server::transaction_flooding_handler),
        )
        .route("/connect", post(server::connect_handler))
        .route("/heartbeat", post(server::heartbeat_handler))
        .with_state((blockchain.clone(), nodes.clone()));
    tokio::spawn(heartbeat(nodes.clone(), local_addr));
    Server::bind(local_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
