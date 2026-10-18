package app

// The camera firmware reports the larger of RTSP client IPs and connected
// recorder callbacks. One virtual lens owns at most one callback connection.
func cameraClientCounts(camera *camera) (streams, ips int) {
	if camera.media != nil {
		streams, ips = camera.media.ClientCounts()
	}
	if camera.callback != nil && camera.callback.snapshot().State == "connected" {
		ips = max(ips, 1)
	}
	return streams, ips
}
