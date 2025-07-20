use std::net::SocketAddr;

pub struct Peer {
    pub sock_addr: SocketAddr,
    pub pub_key: String,
}
