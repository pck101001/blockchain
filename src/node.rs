use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    addr: SocketAddr,
}

pub struct NodeManager {
    nodes: Arc<Mutex<Vec<Node>>>,
}

impl NodeManager {
    pub fn new(localAddr: &SocketAddr) -> Self {
        let nodes = Arc::new(Mutex::new(Vec::new()));
        nodes.lock().unwrap().push(Node { addr: *localAddr });
        NodeManager { nodes }
    }

    pub fn add_node(&mut self, addr: SocketAddr) {
        let mut nodes = self.nodes.lock().unwrap();
        if !nodes.iter().any(|node| node == &Node { addr }) {
            nodes.push(Node { addr });
        }
    }

    pub fn get_nodes(&self) -> Vec<SocketAddr> {
        self.nodes.lock().unwrap().iter().map(|n| n.addr).collect()
    }
}
