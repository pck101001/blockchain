use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
pub struct Config {
    addr: SocketAddr,
}
impl Config {
    pub fn new(mut args: std::env::Args) -> Result<Config, &'static str> {
        if args.len() < 3 {
            return Err("not enough arguments
            usage: blockchain <ip> <port>");
        }
        args.next();
        let ip = match args.next() {
            Some(arg) => arg,
            None => return Err("Didn't get an ip address"),
        };
        let port = match args.next() {
            Some(arg) => arg,
            None => return Err("Didn't get a port number"),
        };
        let addr = format!("{}:{}", ip, port).parse().unwrap();
        Ok(Config { addr })
    }
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConnectRequest {
    pub des_ip: String,
    pub des_port: u16,
    pub src_ip: String,
    pub src_port: u16,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Heartbeat {
    pub addr: SocketAddr,
}
