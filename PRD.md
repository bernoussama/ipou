
# ipou - Product Requirements

## Vision
Fast, secure IP-over-UDP tunnel for connecting distributed networks with minimal overhead.

## Core Features

### Phase 1 - Foundation ✅
- [x] Basic IP-over-UDP tunneling
- [x] TUN interface management
- [x] Automatic peer discovery
- [x] IPv4 packet routing

### Phase 2 - Reliability 🚧
- [ ] Packet validation & checksums
- [ ] Structured logging (tracing)
- [ ] Graceful error handling
- [ ] Connection timeouts

### Phase 3 - Security 🔒
- [ ] AES-GCM encryption
- [ ] Pre-shared key authentication
- [ ] Rate limiting (token bucket)
- [ ] Basic DoS protection

### Phase 4 - Performance ⚡
- [ ] Zero-copy packet processing
- [ ] IPv6 support
- [ ] Multi-threading optimizations
- [ ] Metrics & monitoring

## Success Metrics
- Sub-1ms latency overhead
- >1Gbps throughput
- 99.9% packet delivery
- Secure by default
