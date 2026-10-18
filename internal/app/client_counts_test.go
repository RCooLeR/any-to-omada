package app

import "testing"

func TestCameraClientCountsUseCurrentCallbackState(t *testing.T) {
	camera := &camera{}
	streams, ips := cameraClientCounts(camera)
	if streams != 0 || ips != 0 {
		t.Fatal("camera without downstream consumers reported clients")
	}
	worker := &callback{}
	camera.callback = worker
	for _, state := range []string{"unregistered", "connecting", "connected", "reconnecting", "connected"} {
		worker.mu.Lock()
		worker.status.State = state
		// Historical reconnect and registration counters are not active clients.
		worker.status.Connections = 15
		worker.status.Registrations = 20
		worker.mu.Unlock()
		wantIPs := 0
		if state == "connected" {
			wantIPs = 1
		}
		streams, ips = cameraClientCounts(camera)
		if streams != 0 || ips != wantIPs {
			t.Fatalf("state %s produced %d/%d, want 0/%d", state, streams, ips, wantIPs)
		}
	}
}
