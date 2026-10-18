package omadafront

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

func TestDiscoveryUsesCurrentClientCountsAcrossTransports(t *testing.T) {
	streams, ips := 0, 0
	s := testServer(t, func(cfg *Config) {
		cfg.ClientCounts = func() (int, int) { return streams, ips }
	})
	const body = `{"method":"do","get_rtsp_info":{}}`
	for _, counts := range [][2]int{{0, 0}, {2, 1}, {3, 2}, {0, 1}, {0, 0}} {
		streams, ips = counts[0], counts[1]
		want := map[string]any{"stream_num": float64(streams), "ip_src_num": float64(ips), "error_code": float64(0)}
		for _, path := range []string{"/", "/stok=/ds"} {
			code, got := request(t, s, path, body)
			if code != http.StatusOK || !reflect.DeepEqual(got, want) {
				t.Fatalf("HTTP discovery = %#v, want %#v", got, want)
			}
		}
		var native map[string]any
		if err := json.Unmarshal(s.Passthrough(json.RawMessage(body)), &native); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(native, want) {
			t.Fatalf("callback discovery = %#v, want %#v", native, want)
		}
	}
	if status := s.Status(); status.Sessions != 0 || status.LoginSuccesses != 0 {
		t.Fatal("discovery created an HTTP authentication session")
	}
}

func TestDiscoveryDoesNotExposeNegativeCounts(t *testing.T) {
	s := testServer(t, func(cfg *Config) {
		cfg.ClientCounts = func() (int, int) { return -1, -2 }
	})
	_, got := request(t, s, "/stok=/ds", `{"method":"do","get_rtsp_info":{}}`)
	if got["stream_num"] != float64(0) || got["ip_src_num"] != float64(0) {
		t.Fatal("negative accounting values escaped the discovery response")
	}
}
