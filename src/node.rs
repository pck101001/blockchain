use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    addr: SocketAddr,
    last_seen: SystemTime,
}

pub struct NodeManager {
    nodes: Vec<Node>,
}

impl Node {
    fn new(addr: SocketAddr) -> Self {
        Node {
            addr,
            last_seen: SystemTime::now(),
        }
    }
    fn update_last_seen(&mut self) {
        self.last_seen = SystemTime::now();
    }
    fn is_expired(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed().unwrap_or(Duration::from_secs(0)) > timeout
    }
}

impl NodeManager {
    pub fn new(local_addr: &SocketAddr) -> Self {
        let nodes = vec![Node::new(*local_addr)];
        NodeManager { nodes }
    }

    pub fn add_node(&mut self, addr: SocketAddr) {
        if !self.nodes.iter().any(|node| node.addr == addr) {
            self.nodes.push(Node::new(addr));
        }
    }

    pub fn get_nodes(&self) -> Vec<SocketAddr> {
        self.nodes.iter().map(|n| n.addr).collect()
    }

    pub fn get_local_addr(&self) -> SocketAddr {
        self.nodes[0].addr
    }

    pub fn exists(&self, addr: SocketAddr) -> bool {
        self.nodes.iter().any(|node| node.addr == addr)
    }

    pub fn remove_expired_nodes(&mut self, timeout: Duration) {
        let local_addr = self.get_local_addr();
        self.nodes
            .retain(|node| node.addr == local_addr || !node.is_expired(timeout));
    }

    pub fn update_node(&mut self, addr: SocketAddr) {
        if let Some(node) = self.nodes.iter_mut().find(|node| node.addr == addr) {
            node.update_last_seen();
        } else {
            self.add_node(addr);
        }
    }
}
