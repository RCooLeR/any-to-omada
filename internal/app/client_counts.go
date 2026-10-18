package app

// cameraClientCounts follows the captured firmware count: the larger of RTSP
// client IPs and connected recorder callbacks. A lens owns at most one callback.
func cameraClientCounts(camera *camera) (streams, ips int) {
	if camera.media != nil {
		streams, ips = camera.media.ClientCounts()
	}
	if camera.callback != nil && camera.callback.snapshot().State == "connected" {
		ips = max(ips, 1)
	}
	return streams, ips
}
