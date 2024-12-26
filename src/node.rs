use secp256k1::generate_keypair;
use secp256k1::rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    addr: SocketAddr,
    last_seen: SystemTime,
    private_key: Option<String>,
    public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeManager {
    nodes: Vec<Node>,
}

impl Node {
    pub fn new(addr: SocketAddr) -> Self {
        Node {
            addr,
            last_seen: SystemTime::now(),
            private_key: None,
            public_key: None,
        }
    }

    pub fn init(&mut self) {
        let (private_key, public_key) = generate_keypair(&mut thread_rng());
        self.private_key = Some(hex::encode(private_key.secret_bytes()));
        self.public_key = Some(hex::encode(public_key.serialize()));
    }

    pub fn update_public_key(&mut self, public_key: String) {
        self.public_key = Some(public_key);
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = SystemTime::now();
    }

    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed().unwrap_or(Duration::from_secs(0)) > timeout
    }

    pub fn get_keys(&self) -> (Option<&str>, Option<&str>) {
        (self.private_key.as_deref(), self.public_key.as_deref())
    }
}

impl NodeManager {
    pub fn new(local_addr: &SocketAddr) -> Self {
        let mut nodes = vec![Node::new(*local_addr)];
        nodes[0].init();
        NodeManager { nodes }
    }

    pub fn add_node(&mut self, addr: SocketAddr, public_key: String) {
        if !self.nodes.iter().any(|node| node.addr == addr) {
            let mut node = Node::new(addr);
            node.update_public_key(public_key);
            self.nodes.push(node);
        }
    }

    pub fn get_nodes_addr(&self) -> Vec<SocketAddr> {
        self.nodes.iter().map(|n| n.addr).collect()
    }

    pub fn get_nodes(&self) -> Vec<Node> {
        self.nodes.iter().skip(1).cloned().collect()
    }

    pub fn get_local_addr(&self) -> SocketAddr {
        self.nodes[0].addr
    }

    pub fn get_local_keys(&self) -> (Option<&str>, Option<&str>) {
        self.nodes[0].get_keys()
    }

    pub fn get_local_public_key(&self) -> String {
        self.nodes[0]
            .public_key
            .as_ref()
            .map(|key| String::from("0x") + key)
            .unwrap_or_else(|| String::from("0x"))
    }

    pub fn exists(&self, addr: SocketAddr) -> bool {
        self.nodes.iter().any(|node| node.addr == addr)
    }

    pub fn remove_expired_nodes(&mut self, timeout: Duration) {
        let local_addr = self.get_local_addr();
        self.nodes
            .retain(|node| node.addr == local_addr || !node.is_expired(timeout));
    }

    pub fn update_node(&mut self, addr: SocketAddr, public_key: String) {
        if let Some(node) = self.nodes.iter_mut().find(|node| node.addr == addr) {
            node.update_last_seen();
        } else {
            self.add_node(addr, public_key);
        }
    }
}
