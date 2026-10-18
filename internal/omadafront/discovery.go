package omadafront

// streamDiscovery reports active downstream streams and distinct clients;
// missing counters become zero, not the number of configured video profiles.
func (s *Server) streamDiscovery() map[string]any {
	streams, ips := 0, 0
	if s.clientCounts != nil {
		streams, ips = s.clientCounts()
	}
	return map[string]any{"stream_num": max(0, streams), "ip_src_num": max(0, ips), "error_code": 0}
}
