use crate::protocol::{InitiatePunch, PacketType, ProtocolPacket};
use crate::state::StateManager;
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};
use tokio::time::sleep;

/// Tracks active hole punching sessions
#[derive(Debug, Clone)]
pub struct PunchSession {
    pub punch_id: [u8; 16],
    pub target_peer: [u8; 32],
    pub target_endpoint: SocketAddr,
    pub started_at: SystemTime,
    pub attempts: u32,
}

/// Manages NAT hole punching coordination
pub struct PunchManager {
    state_manager: StateManager,
    our_public_key: [u8; 32],
    /// Active punch sessions
    active_sessions: Arc<RwLock<HashMap<[u8; 16], PunchSession>>>,
}

impl PunchManager {
    pub fn new(state_manager: StateManager, public_key: [u8; 32]) -> Self {
        Self {
            state_manager,
            our_public_key: public_key,
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initiate hole punching from anchor to both peers
    pub async fn initiate_punch(
        &self,
        peer_a: [u8; 32],
        peer_a_endpoint: SocketAddr,
        peer_b: [u8; 32],
        peer_b_endpoint: SocketAddr,
        send_channel: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) -> crate::Result<()> {
        // Generate unique punch ID
        let mut punch_id = [0u8; 16];
        rand::rng().fill_bytes(&mut punch_id);

        // Send initiate punch to peer A
        let punch_a = InitiatePunch {
            target_peer: peer_b,
            target_endpoint: peer_b_endpoint,
            punch_id,
        };

        let payload_a = serde_yml::to_string(&punch_a)?.into_bytes();
        let session_id_a = self
            .state_manager
            .get_session_id(&peer_a)
            .await
            .unwrap_or_else(|| StateManager::generate_session_id());
        let sequence_a = self.state_manager.next_sequence(peer_a).await;

        let packet_a = ProtocolPacket::new(
            PacketType::InitiatePunch,
            self.our_public_key,
            session_id_a,
            sequence_a,
            payload_a,
        );

        // Send initiate punch to peer B
        let punch_b = InitiatePunch {
            target_peer: peer_a,
            target_endpoint: peer_a_endpoint,
            punch_id,
        };

        let payload_b = serde_yml::to_string(&punch_b)?.into_bytes();
        let session_id_b = self
            .state_manager
            .get_session_id(&peer_b)
            .await
            .unwrap_or_else(|| StateManager::generate_session_id());
        let sequence_b = self.state_manager.next_sequence(peer_b).await;

        let packet_b = ProtocolPacket::new(
            PacketType::InitiatePunch,
            self.our_public_key,
            session_id_b,
            sequence_b,
            payload_b,
        );

        // Send both packets
        let packet_a_bytes = packet_a.to_bytes()?;
        let packet_b_bytes = packet_b.to_bytes()?;

        if let Err(e) = send_channel.send((packet_a_bytes, peer_a_endpoint)).await {
            eprintln!("Failed to send punch initiate to peer A: {}", e);
        }

        if let Err(e) = send_channel.send((packet_b_bytes, peer_b_endpoint)).await {
            eprintln!("Failed to send punch initiate to peer B: {}", e);
        }

        println!(
            "Initiated hole punching between {:?} and {:?} with punch ID {:?}",
            peer_a, peer_b, punch_id
        );

        Ok(())
    }

    /// Handle initiate punch packet (peer receives this from anchor)
    pub async fn handle_initiate_punch(
        &self,
        packet: ProtocolPacket,
        sender_endpoint: SocketAddr,
        send_channel: mpsc::Sender<(Vec<u8>, SocketAddr)>,
        max_attempts: u32,
        _punch_timeout: u64,
    ) -> crate::Result<()> {
        // Parse punch initiation payload
        let payload_str = std::str::from_utf8(&packet.payload)?;
        let punch_init: InitiatePunch = serde_yml::from_str(payload_str)?;

        // Mark packet received
        self.state_manager
            .mark_packet_received(packet.sender_id, packet.sequence, sender_endpoint)
            .await;

        println!(
            "Received punch initiation for target {:?} at {:?}",
            punch_init.target_peer, punch_init.target_endpoint
        );

        // Start hole punching session
        let session = PunchSession {
            punch_id: punch_init.punch_id,
            target_peer: punch_init.target_peer,
            target_endpoint: punch_init.target_endpoint,
            started_at: SystemTime::now(),
            attempts: 0,
        };

        // Store the session
        {
            let mut sessions = self.active_sessions.write().await;
            sessions.insert(punch_init.punch_id, session.clone());
        }

        // Start punch attempts in background
        let active_sessions = self.active_sessions.clone();
        let state_manager = self.state_manager.clone();
        let our_key = self.our_public_key;
        
        tokio::spawn(async move {
            Self::perform_punch_attempts(
                active_sessions,
                state_manager,
                our_key,
                session,
                send_channel,
                max_attempts,
                _punch_timeout,
            )
            .await;
        });

        Ok(())
    }

    /// Perform the actual hole punching attempts
    async fn perform_punch_attempts(
        active_sessions: Arc<RwLock<HashMap<[u8; 16], PunchSession>>>,
        state_manager: StateManager,
        our_key: [u8; 32],
        mut session: PunchSession,
        send_channel: mpsc::Sender<(Vec<u8>, SocketAddr)>,
        max_attempts: u32,
        _punch_timeout: u64,
    ) {
        for attempt in 1..=max_attempts {
            session.attempts = attempt;

            // Create a simple punch packet (VPN data with minimal payload)
            let session_id = state_manager
                .get_session_id(&session.target_peer)
                .await
                .unwrap_or_else(|| StateManager::generate_session_id());
            let sequence = state_manager.next_sequence(session.target_peer).await;

            let punch_packet = ProtocolPacket::new(
                PacketType::VpnData,
                our_key,
                session_id,
                sequence,
                vec![0u8; 4], // Minimal punch payload
            );

            if let Ok(packet_bytes) = punch_packet.to_bytes() {
                if let Err(e) = send_channel
                    .send((packet_bytes, session.target_endpoint))
                    .await
                {
                    eprintln!("Failed to send punch packet attempt {}: {}", attempt, e);
                    break;
                }

                println!(
                    "Sent punch attempt {} to {:?}",
                    attempt, session.target_endpoint
                );
            }

            // Wait between attempts (exponential backoff)
            let delay_ms = 100 * (1 << (attempt - 1).min(4)); // Max 1.6s delay
            sleep(Duration::from_millis(delay_ms)).await;
        }

        // Remove session after completion
        {
            let mut sessions = active_sessions.write().await;
            sessions.remove(&session.punch_id);
        }

        println!(
            "Completed hole punching attempts for punch ID {:?}",
            session.punch_id
        );
    }

    /// Clean up expired punch sessions
    pub async fn cleanup_expired_sessions(&self, timeout_seconds: u64) {
        let mut sessions = self.active_sessions.write().await;
        let now = SystemTime::now();

        sessions.retain(|punch_id, session| {
            if let Ok(duration) = now.duration_since(session.started_at) {
                if duration.as_secs() > timeout_seconds {
                    println!("Cleaning up expired punch session {:?}", punch_id);
                    return false;
                }
            }
            true
        });
    }

    /// Get active punch sessions count
    pub async fn active_sessions_count(&self) -> usize {
        let sessions = self.active_sessions.read().await;
        sessions.len()
    }
}