use std::sync::{Arc, Mutex};
use axum::{routing::{get,post},Router,response::Html};
use axum_server::Server;
use tower_http::services::ServeDir;
use std::env;
use std::process;

mod server;
mod block;
mod blockchain;
mod node;
mod transaction;
mod mining;
mod utils;

#[tokio::main]
async fn main(){
    let localAddr=utils::Config::new(env::args()).unwrap_or_else(|err|{
        eprintln!("Problem parsing arguments: {}",err);
        process::exit(1);
    }).addr();
    let blockchain=Arc::new(Mutex::new(blockchain::Blockchain::new()));
    let nodes=Arc::new(Mutex::new(node::NodeManager::new(&localAddr)));

    let app=Router::new()
        .nest_service("/static",ServeDir::new("static"))
        .route("/",get(|| async {Html(include_str!("../templates/index.html"))}))
        .with_state((blockchain.clone(),nodes.clone()));
    
    Server::bind(localAddr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}