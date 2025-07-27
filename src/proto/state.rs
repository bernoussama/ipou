use std::net::SocketAddr;

use crate::{
    crypto::PublicKeyBytes,
    proto::{self, Timestamp},
};

#[derive(Debug)]
pub enum PeerState {
    Unknown,
    Connecting,
    Connected,
    Stale,  // havent heard from peer in a while
    Failed, // Connection attemps failed
}

#[derive(Debug)]
pub struct PeerConnection {
    pub pubkey: PublicKeyBytes,
    pub state: PeerState,
    pub last_endpoint: Option<SocketAddr>,
    pub last_seen: Timestamp,
    pub failed_attempts: u16,
}

impl PeerConnection {
    pub fn new(pubkey: PublicKeyBytes) -> Self {
        Self {
            pubkey,
            state: PeerState::Unknown,
            last_endpoint: None,
            last_seen: 0,
            failed_attempts: 0,
        }
    }

    pub fn mark_connecting(&mut self) {
        self.state = PeerState::Connecting;
        #[cfg(debug_assertions)]
        println!("Peer {} is now connecting", base64::encode(self.pubkey));
    }

    pub fn mark_connected(&mut self, endpoint: SocketAddr) {
        self.state = PeerState::Connected;
        self.last_endpoint = Some(endpoint);
        self.last_seen = proto::now();
        self.failed_attempts = 0;
        #[cfg(debug_assertions)]
        println!(
            "Peer {} is now connected at {endpoint:?}",
            base64::encode(self.pubkey)
        );
    }

    pub fn mark_stale(&mut self) {
        self.state = PeerState::Stale;
        #[cfg(debug_assertions)]
        println!("Peer {} is now stale", base64::encode(self.pubkey));
    }
    pub fn mark_failed(&mut self) {
        self.state = PeerState::Failed;
        self.failed_attempts += 1;
        #[cfg(debug_assertions)]
        println!(
            "Peer {} connection failed, attempts: {}",
            base64::encode(self.pubkey),
            self.failed_attempts
        );
    }
    pub fn seen(&mut self) {
        self.last_seen = proto::now();
    }

    pub fn is_connected(&self) -> bool {
        matches!(self.state, PeerState::Connected)
    }

    pub fn is_stale(&self) -> bool {
        matches!(self.state, PeerState::Stale)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // Helper function to create a mock PublicKeyBytes for testing
    fn mock_pubkey() -> PublicKeyBytes {
        [1u8; 32] // Standard 32-byte public key
    }

    fn mock_pubkey_different() -> PublicKeyBytes {
        [2u8; 32] // Different public key for comparison tests
    }

    fn mock_socket_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    }

    fn mock_socket_addr_v6() -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080)
    }

    #[test]
    fn test_peer_connection_new() {
        let pubkey = mock_pubkey();
        let peer = PeerConnection::new(pubkey);
        
        assert_eq!(peer.pubkey, pubkey);
        assert!(matches!(peer.state, PeerState::Unknown));
        assert_eq!(peer.last_endpoint, None);
        assert_eq!(peer.last_seen, 0);
        assert_eq!(peer.failed_attempts, 0);
    }

    #[test]
    fn test_peer_state_debug_formatting() {
        // Test Debug implementation for all PeerState variants
        assert_eq!(format!("{:?}", PeerState::Unknown), "Unknown");
        assert_eq!(format!("{:?}", PeerState::Connecting), "Connecting");
        assert_eq!(format!("{:?}", PeerState::Connected), "Connected");
        assert_eq!(format!("{:?}", PeerState::Stale), "Stale");
        assert_eq!(format!("{:?}", PeerState::Failed), "Failed");
    }

    #[test]
    fn test_peer_connection_debug_formatting() {
        let peer = PeerConnection::new(mock_pubkey());
        let debug_str = format!("{:?}", peer);
        
        // Verify that the debug output contains expected fields
        assert!(debug_str.contains("PeerConnection"));
        assert!(debug_str.contains("pubkey"));
        assert!(debug_str.contains("state"));
        assert!(debug_str.contains("last_endpoint"));
        assert!(debug_str.contains("last_seen"));
        assert!(debug_str.contains("failed_attempts"));
    }

    #[test]
    fn test_mark_connecting_state_transition() {
        let mut peer = PeerConnection::new(mock_pubkey());
        
        // Initially should be Unknown
        assert!(matches!(peer.state, PeerState::Unknown));
        
        peer.mark_connecting();
        
        // State should change to Connecting
        assert!(matches!(peer.state, PeerState::Connecting));
        
        // Other fields should remain unchanged
        assert_eq!(peer.last_endpoint, None);
        assert_eq!(peer.last_seen, 0);
        assert_eq!(peer.failed_attempts, 0);
    }

    #[test]
    fn test_mark_connecting_from_different_states() {
        let mut peer = PeerConnection::new(mock_pubkey());
        
        // Test from Failed state
        peer.state = PeerState::Failed;
        peer.mark_connecting();
        assert!(matches!(peer.state, PeerState::Connecting));
        
        // Test from Stale state
        peer.state = PeerState::Stale;
        peer.mark_connecting();
        assert!(matches!(peer.state, PeerState::Connecting));
        
        // Test from Connected state
        peer.state = PeerState::Connected;
        peer.mark_connecting();
        assert!(matches!(peer.state, PeerState::Connecting));
    }

    #[test]
    fn test_mark_connected_state_and_fields() {
        let mut peer = PeerConnection::new(mock_pubkey());
        let endpoint = mock_socket_addr();
        
        // Set some initial failed attempts to test reset
        peer.failed_attempts = 5;
        
        peer.mark_connected(endpoint);
        
        // Verify state change
        assert!(matches!(peer.state, PeerState::Connected));
        
        // Verify endpoint is saved
        assert_eq!(peer.last_endpoint, Some(endpoint));
        
        // Verify timestamp is updated (should not be 0)
        assert_ne!(peer.last_seen, 0);
        
        // Verify failed attempts are reset
        assert_eq!(peer.failed_attempts, 0);
    }

    #[test]
    fn test_mark_connected_with_ipv6() {
        let mut peer = PeerConnection::new(mock_pubkey());
        let endpoint = mock_socket_addr_v6();
        
        peer.mark_connected(endpoint);
        
        assert!(matches!(peer.state, PeerState::Connected));
        assert_eq!(peer.last_endpoint, Some(endpoint));
        assert!(peer.is_connected());
    }

    #[test]
    fn test_mark_connected_resets_failed_attempts() {
        let mut peer = PeerConnection::new(mock_pubkey());
        
        // Set high failed attempts count
        peer.failed_attempts = 10;
        
        peer.mark_connected(mock_socket_addr());
        
        // Should be reset to 0
        assert_eq!(peer.failed_attempts, 0);
    }

    #[test]
    fn test_mark_connected_updates_endpoint() {
        let mut peer = PeerConnection::new(mock_pubkey());
        let endpoint1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let endpoint2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9090);
        
        // Connect to first endpoint
        peer.mark_connected(endpoint1);
        assert_eq!(peer.last_endpoint, Some(endpoint1));
        
        // Connect to different endpoint
        peer.mark_connected(endpoint2);
        assert_eq!(peer.last_endpoint, Some(endpoint2));
    }

    #[test]
    fn test_mark_stale_state_transition() {
        let mut peer = PeerConnection::new(mock_pubkey());
        
        peer.mark_stale();
        
        assert!(matches!(peer.state, PeerState::Stale));
        
        // Other fields should remain unchanged from initial state
        assert_eq!(peer.last_endpoint, None);
        assert_eq!(peer.last_seen, 0);
        assert_eq!(peer.failed_attempts, 0);
    }

    #[test]
    fn test_mark_stale_preserves_connection_data() {
        let mut peer = PeerConnection::new(mock_pubkey());
        let endpoint = mock_socket_addr();
        
        // First establish a connection
        peer.mark_connected(endpoint);
        let timestamp = peer.last_seen;
        
        // Then mark as stale
        peer.mark_stale();
        
        // State should change but connection data should be preserved
        assert!(matches!(peer.state, PeerState::Stale));
        assert_eq!(peer.last_endpoint, Some(endpoint));
        assert_eq!(peer.last_seen, timestamp);
        // failed_attempts should remain 0 (was reset by mark_connected)
        assert_eq!(peer.failed_attempts, 0);
    }

    #[test]
    fn test_mark_failed_increments_attempts() {
        let mut peer = PeerConnection::new(mock_pubkey());
        let initial_attempts = peer.failed_attempts;
        
        peer.mark_failed();
        
        assert!(matches!(peer.state, PeerState::Failed));
        assert_eq!(peer.failed_attempts, initial_attempts + 1);
    }

    #[test]
    fn test_mark_failed_multiple_times() {
        let mut peer = PeerConnection::new(mock_pubkey());
        
        // Test multiple consecutive failures
        peer.mark_failed();
        assert_eq!(peer.failed_attempts, 1);
        assert!(matches!(peer.state, PeerState::Failed));
        
        peer.mark_failed();
        assert_eq!(peer.failed_attempts, 2);
        
        peer.mark_failed();
        assert_eq!(peer.failed_attempts, 3);
        
        // State should remain Failed
        assert!(matches!(peer.state, PeerState::Failed));
    }

    #[test]
    fn test_mark_failed_overflow_behavior() {
        let mut peer = PeerConnection::new(mock_pubkey());
        
        // Set to maximum value - testing edge case
        peer.failed_attempts = u16::MAX - 1;
        
        peer.mark_failed();
        assert_eq!(peer.failed_attempts, u16::MAX);
        assert!(matches!(peer.state, PeerState::Failed));
        
        // Test actual overflow behavior
        peer.mark_failed();
        // This will wrap around to 0 due to overflow
        assert_eq!(peer.failed_attempts, 0);
    }

    #[test]
    fn test_seen_updates_timestamp() {
        let mut peer = PeerConnection::new(mock_pubkey());
        let initial_timestamp = peer.last_seen;
        
        peer.seen();
        
        // Timestamp should be updated and not be the initial value
        assert_ne!(peer.last_seen, initial_timestamp);
        assert_ne!(peer.last_seen, 0);
    }

    #[test]
    fn test_seen_multiple_calls() {
        let mut peer = PeerConnection::new(mock_pubkey());
        
        peer.seen();
        let first_timestamp = peer.last_seen;
        
        // Call again
        peer.seen();
        let second_timestamp = peer.last_seen;
        
        // Both should be valid timestamps
        assert_ne!(first_timestamp, 0);
        assert_ne!(second_timestamp, 0);
        
        // Second should be >= first (allowing for same time in tests)
        assert!(second_timestamp >= first_timestamp);
    }

    #[test]
    fn test_is_connected_positive_case() {
        let mut peer = PeerConnection::new(mock_pubkey());
        peer.state = PeerState::Connected;
        
        assert!(peer.is_connected());
    }

    #[test]
    fn test_is_connected_negative_cases() {
        let mut peer = PeerConnection::new(mock_pubkey());
        
        // Test all non-Connected states
        peer.state = PeerState::Unknown;
        assert!(!peer.is_connected());
        
        peer.state = PeerState::Connecting;
        assert!(!peer.is_connected());
        
        peer.state = PeerState::Stale;
        assert!(!peer.is_connected());
        
        peer.state = PeerState::Failed;
        assert!(!peer.is_connected());
    }

    #[test]
    fn test_is_stale_positive_case() {
        let mut peer = PeerConnection::new(mock_pubkey());
        peer.state = PeerState::Stale;
        
        assert!(peer.is_stale());
    }

    #[test]
    fn test_is_stale_negative_cases() {
        let mut peer = PeerConnection::new(mock_pubkey());
        
        // Test all non-Stale states
        peer.state = PeerState::Unknown;
        assert!(!peer.is_stale());
        
        peer.state = PeerState::Connecting;
        assert!(!peer.is_stale());
        
        peer.state = PeerState::Connected;
        assert!(!peer.is_stale());
        
        peer.state = PeerState::Failed;
        assert!(!peer.is_stale());
    }

    #[test]
    fn test_complete_state_transition_flow() {
        let mut peer = PeerConnection::new(mock_pubkey());
        let endpoint = mock_socket_addr();
        
        // Start from Unknown
        assert!(matches!(peer.state, PeerState::Unknown));
        assert!(!peer.is_connected());
        assert!(!peer.is_stale());
        
        // Move to Connecting
        peer.mark_connecting();
        assert!(matches!(peer.state, PeerState::Connecting));
        assert!(!peer.is_connected());
        assert!(!peer.is_stale());
        
        // Move to Connected
        peer.mark_connected(endpoint);
        assert!(matches!(peer.state, PeerState::Connected));
        assert!(peer.is_connected());
        assert!(!peer.is_stale());
        
        // Move to Stale
        peer.mark_stale();
        assert!(matches!(peer.state, PeerState::Stale));
        assert!(!peer.is_connected());
        assert!(peer.is_stale());
        
        // Move to Failed
        peer.mark_failed();
        assert!(matches!(peer.state, PeerState::Failed));
        assert!(!peer.is_connected());
        assert!(!peer.is_stale());
        assert_eq!(peer.failed_attempts, 1);
    }

    #[test]
    fn test_recovery_after_failure() {
        let mut peer = PeerConnection::new(mock_pubkey());
        let endpoint = mock_socket_addr();
        
        // Simulate multiple failures
        peer.mark_failed();
        peer.mark_failed();
        peer.mark_failed();
        assert_eq!(peer.failed_attempts, 3);
        assert!(matches!(peer.state, PeerState::Failed));
        
        // Recovery by successful connection
        peer.mark_connected(endpoint);
        assert!(matches!(peer.state, PeerState::Connected));
        assert_eq!(peer.failed_attempts, 0); // Should be reset
        assert!(peer.is_connected());
    }

    #[test]
    fn test_different_public_keys() {
        let pubkey1 = mock_pubkey();
        let pubkey2 = mock_pubkey_different();
        
        let peer1 = PeerConnection::new(pubkey1);
        let peer2 = PeerConnection::new(pubkey2);
        
        assert_ne!(peer1.pubkey, peer2.pubkey);
        assert_eq!(peer1.pubkey, pubkey1);
        assert_eq!(peer2.pubkey, pubkey2);
        
        // Both should start in the same initial state
        assert!(matches!(peer1.state, PeerState::Unknown));
        assert!(matches!(peer2.state, PeerState::Unknown));
    }

    #[test]
    fn test_endpoint_port_variations() {
        let mut peer = PeerConnection::new(mock_pubkey());
        
        // Test different ports including edge cases
        let endpoint1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let endpoint2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let endpoint3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 65535);
        let endpoint4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        
        peer.mark_connected(endpoint1);
        assert_eq!(peer.last_endpoint, Some(endpoint1));
        
        peer.mark_connected(endpoint2);
        assert_eq!(peer.last_endpoint, Some(endpoint2));
        
        peer.mark_connected(endpoint3);
        assert_eq!(peer.last_endpoint, Some(endpoint3));
        
        peer.mark_connected(endpoint4);
        assert_eq!(peer.last_endpoint, Some(endpoint4));
    }

    #[test]
    fn test_endpoint_ip_variations() {
        let mut peer = PeerConnection::new(mock_pubkey());
        
        // Test different IP addresses
        let localhost_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let private_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let localhost_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080);
        
        peer.mark_connected(localhost_v4);
        assert_eq!(peer.last_endpoint, Some(localhost_v4));
        assert!(peer.is_connected());
        
        peer.mark_connected(private_v4);
        assert_eq!(peer.last_endpoint, Some(private_v4));
        
        peer.mark_connected(localhost_v6);
        assert_eq!(peer.last_endpoint, Some(localhost_v6));
    }

    #[test]
    fn test_state_consistency_after_operations() {
        let mut peer = PeerConnection::new(mock_pubkey());
        let endpoint = mock_socket_addr();
        
        // Perform a sequence of operations
        peer.mark_connecting();
        peer.seen(); // Should update timestamp even while connecting
        
        let connecting_timestamp = peer.last_seen;
        assert_ne!(connecting_timestamp, 0);
        
        peer.mark_connected(endpoint);
        let connected_timestamp = peer.last_seen;
        
        // Connected timestamp should be >= connecting timestamp
        assert!(connected_timestamp >= connecting_timestamp);
        
        peer.seen(); // Update timestamp while connected
        let final_timestamp = peer.last_seen;
        assert!(final_timestamp >= connected_timestamp);
    }

    #[test]
    fn test_failed_attempts_boundary_values() {
        let mut peer = PeerConnection::new(mock_pubkey());
        
        // Test starting from 0
        assert_eq!(peer.failed_attempts, 0);
        
        // Test increment
        peer.mark_failed();
        assert_eq!(peer.failed_attempts, 1);
        
        // Test reset via connection
        peer.mark_connected(mock_socket_addr());
        assert_eq!(peer.failed_attempts, 0);
        
        // Test multiple failures up to a reasonable number
        for expected_count in 1..=100 {
            peer.mark_failed();
            assert_eq!(peer.failed_attempts, expected_count);
        }
    }

    #[test]
    fn test_pubkey_bytes_content() {
        let pubkey1 = [0u8; 32];
        let pubkey2 = [255u8; 32];
        let mut pubkey3 = [0u8; 32];
        pubkey3[0] = 1;
        pubkey3[31] = 1;
        
        let peer1 = PeerConnection::new(pubkey1);
        let peer2 = PeerConnection::new(pubkey2);
        let peer3 = PeerConnection::new(pubkey3);
        
        assert_eq!(peer1.pubkey, pubkey1);
        assert_eq!(peer2.pubkey, pubkey2);
        assert_eq!(peer3.pubkey, pubkey3);
        
        assert_ne!(peer1.pubkey, peer2.pubkey);
        assert_ne!(peer1.pubkey, peer3.pubkey);
        assert_ne!(peer2.pubkey, peer3.pubkey);
    }

    #[test]
    fn test_concurrent_state_changes() {
        let mut peer = PeerConnection::new(mock_pubkey());
        let endpoint = mock_socket_addr();
        
        // Simulate rapid state changes that might occur in concurrent scenarios
        peer.mark_connecting();
        peer.mark_failed();
        peer.mark_connecting();
        peer.mark_connected(endpoint);
        
        // Final state should be consistent
        assert!(matches!(peer.state, PeerState::Connected));
        assert_eq!(peer.last_endpoint, Some(endpoint));
        assert_eq!(peer.failed_attempts, 0);
        assert_ne!(peer.last_seen, 0);
    }

    #[test]
    fn test_timestamp_using_proto_now() {
        let mut peer = PeerConnection::new(mock_pubkey());
        
        // Test that mark_connected uses proto::now()
        peer.mark_connected(mock_socket_addr());
        let connected_timestamp = peer.last_seen;
        
        // Test that seen() uses proto::now()
        peer.seen();
        let seen_timestamp = peer.last_seen;
        
        // Both should be reasonable Unix timestamps (> year 2020)
        assert!(connected_timestamp > 1577836800); // Jan 1, 2020
        assert!(seen_timestamp > 1577836800);
        
        // Seen timestamp should be >= connected timestamp
        assert!(seen_timestamp >= connected_timestamp);
    }

    #[test]
    fn test_timestamp_progression() {
        let mut peer = PeerConnection::new(mock_pubkey());
        
        // Test that timestamps generally increase or stay the same
        peer.seen();
        let t1 = peer.last_seen;
        
        peer.seen();
        let t2 = peer.last_seen;
        
        peer.mark_connected(mock_socket_addr());
        let t3 = peer.last_seen;
        
        peer.seen();
        let t4 = peer.last_seen;
        
        // All timestamps should be non-zero and reasonable
        assert_ne!(t1, 0);
        assert_ne!(t2, 0);
        assert_ne!(t3, 0);
        assert_ne!(t4, 0);
        
        // Should generally be non-decreasing (allowing for same values in fast tests)
        assert!(t2 >= t1);
        assert!(t3 >= t2);
        assert!(t4 >= t3);
    }

    #[test]
    fn test_state_transition_edge_cases() {
        let mut peer = PeerConnection::new(mock_pubkey());
        let endpoint = mock_socket_addr();
        
        // Test transitioning from Connected back to Connecting
        peer.mark_connected(endpoint);
        assert!(peer.is_connected());
        
        peer.mark_connecting();
        assert!(!peer.is_connected());
        assert!(matches!(peer.state, PeerState::Connecting));
        
        // Test transitioning from Stale to Connected
        peer.mark_stale();
        assert!(peer.is_stale());
        
        peer.mark_connected(endpoint);
        assert!(peer.is_connected());
        assert!(!peer.is_stale());
    }
}
