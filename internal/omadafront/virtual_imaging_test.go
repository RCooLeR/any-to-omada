package omadafront

import (
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"testing"
)

func imagingReadback(t *testing.T, s *Server) (string, string) {
	t.Helper()
	var result map[string]any
	err := json.Unmarshal(s.Passthrough(json.RawMessage(`{"method":"get","image":{"name":"switch"},"video":{"name":"common"}}`)), &result)
	if err != nil || result["error_code"] != float64(0) {
		t.Fatal("virtual imaging read failed")
	}
	image := metadataObject(t, metadataObject(t, result["image"])["switch"])
	video := metadataObject(t, metadataObject(t, result["video"])["common"])
	flicker, flickerOK := image["flicker"].(string)
	rate, rateOK := video["sensor_framerate"].(string)
	if !flickerOK || !rateOK {
		t.Fatal("virtual imaging values lost their captured string types")
	}
	return flicker, rate
}

func TestVirtualImagingSharesAuthenticatedHTTPAndCallbackState(t *testing.T) {
	s := testServer(t, nil)
	body := `{"method":"set","image":{"switch":{"flicker":"60hz"}},"video":{"common":{"sensor_framerate":"30"}}}`
	if code, _ := request(t, s, "/stok=/ds", body); code != http.StatusUnauthorized {
		t.Fatal("unauthenticated imaging write was accepted")
	}
	if flicker, rate := imagingReadback(t, s); flicker != "50hz" || rate != "25" {
		t.Fatal("unauthenticated write changed virtual defaults")
	}
	path := login(t, s)
	if code, result := request(t, s, path, body); code != http.StatusOK || result["error_code"] != float64(0) {
		t.Fatal("authenticated combined imaging write failed")
	}
	if flicker, rate := imagingReadback(t, s); flicker != "60hz" || rate != "30" {
		t.Fatal("callback did not read both HTTP settings")
	}
	var result map[string]any
	if err := json.Unmarshal(s.Passthrough(json.RawMessage(`{"method":"set","image":{"switch":{"flicker":"50hz"}},"video":{"common":{"sensor_framerate":"25"}}}`)), &result); err != nil || result["error_code"] != float64(0) {
		t.Fatal("captured enrollment SET failed on the authenticated callback")
	}
	_, result = request(t, s, path, `{"method":"get","image":{"name":"switch"},"video":{"name":"common"}}`)
	image := metadataObject(t, metadataObject(t, result["image"])["switch"])
	video := metadataObject(t, metadataObject(t, result["video"])["common"])
	if image["flicker"] != "50hz" || video["sensor_framerate"] != "25" {
		t.Fatal("HTTP did not read callback settings")
	}
}

func TestVirtualImagingRejectsUnknownFieldsAndMalformedValuesAtomically(t *testing.T) {
	cases := []string{
		`{"method":"set","image":{"switch":{"flicker":"60hz"}},"video":{"common":{"sensor_framerate":"60"}}}`,
		`{"method":"set","image":{"switch":{"flicker":"auto"}},"video":{"common":{"sensor_framerate":"30"}}}`,
		`{"method":"set","image":{"switch":{"flicker":"60hz"}},"video":{"common":{"sensor_framerate":30}}}`,
		`{"method":"set","image":{"switch":{"flicker":null}},"video":{"common":{"sensor_framerate":"30"}}}`,
		`{"method":"set","image":{"switch":{"flicker":"60hz","unknown":true}},"video":{"common":{"sensor_framerate":"30"}}}`,
		`{"method":"set","image":{"switch":{"flicker":"60hz"},"para":{}},"video":{"common":{"sensor_framerate":"30"}}}`,
		`{"method":"set","image":{"switch":{"flicker":"60hz"}},"video":{"common":null}}`,
		`{"method":"set","image":{"switch":{"flicker":"60hz"}},"system":{"basic":{"time_format":1}}}`,
		`{"method":"set","video":{"main":{"frame_rate":"65566"}}}`,
		`{"method":"set","image":{}}`,
		`{"method":"set"}`,
		`{"method":"do","image":{"switch":{"flicker":"60hz"}},"video":{"common":{"sensor_framerate":"30"}}}`,
	}
	for _, transport := range []string{"HTTP", "callback"} {
		t.Run(transport, func(t *testing.T) {
			s := testServer(t, nil)
			path := login(t, s)
			for _, body := range cases {
				var result map[string]any
				if transport == "HTTP" {
					_, result = request(t, s, path, body)
				} else if err := json.Unmarshal(s.Passthrough(json.RawMessage(body)), &result); err != nil {
					t.Fatal(err)
				}
				if result["error_code"] != float64(unsupportedCode) {
					t.Fatalf("invalid imaging write accepted: %s", body)
				}
				if flicker, rate := imagingReadback(t, s); flicker != "50hz" || rate != "25" {
					t.Fatalf("rejected request partly changed virtual state: %s", body)
				}
				if timeSection(t, s.virtualTime, "basic")["time_format"] != 0 {
					// The default is 0; the mixed write above must not be dispatched
					// as a separate time operation while imaging fails.
					t.Fatal("mixed request changed unrelated virtual time")
				}
			}
		})
	}
}

func TestVirtualImagingKeepsIndependentSectionsCamerasAndSourceMetadata(t *testing.T) {
	s := testServer(t, nil)
	other := testServer(t, nil)
	actual := Metadata{Video: map[string]VideoMetadata{"main": {Codec: "H264", Width: 640, Height: 480, FrameRateNumerator: 15, FrameRateDenominator: 1}}}
	s.metadata = func() Metadata { return actual }
	before, _ := s.readSection("video", "main", actual)
	path := login(t, s)
	for _, body := range []string{
		`{"method":"set","image":{"switch":{"flicker":"60hz"}}}`,
		`{"method":"set","video":{"common":{"sensor_framerate":"30"}}}`,
	} {
		if _, result := request(t, s, path, body); result["error_code"] != float64(0) {
			t.Fatal("independent virtual section write failed")
		}
	}
	if flicker, rate := imagingReadback(t, s); flicker != "60hz" || rate != "30" {
		t.Fatal("individual writes were not merged")
	}
	if flicker, rate := imagingReadback(t, other); flicker != "50hz" || rate != "25" {
		t.Fatal("one virtual camera changed another camera's state")
	}
	after, _ := s.readSection("video", "main", actual)
	if !reflect.DeepEqual(before, after) || actual.Video["main"].FrameRateNumerator != 15 {
		t.Fatal("simulated settings changed actual source stream metadata")
	}
}

func TestVirtualImagingDiagnosticsUseObservedSectionNames(t *testing.T) {
	var request map[string]json.RawMessage
	if err := json.Unmarshal([]byte(`{"method":"set","image":{"switch":{"flicker":"50hz"}},"video":{"common":{"sensor_framerate":"25"}}}`), &request); err != nil {
		t.Fatal(err)
	}
	if labels := writeOperationLabels(request); !slices.Equal(labels, []string{"image.switch", "video.common"}) {
		t.Fatalf("captured imaging write was mislabeled: %v", labels)
	}
}
