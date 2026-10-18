package omadafront

import (
	"encoding/json"
	"sync"
)

// virtualImagingState emulates the recorder's image/video configuration for
// one virtual camera. It never changes the physical source's exposure, sensor
// or encoder and does not replace the actual main/minor stream metadata.
type virtualImagingState struct {
	mu              sync.Mutex
	flicker         string
	sensorFrameRate string
}

func newVirtualImagingState() *virtualImagingState {
	return &virtualImagingState{flicker: "50hz", sensorFrameRate: "25"}
}

func (v *virtualImagingState) read(module, name string) (any, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	switch {
	case module == "image" && name == "switch":
		return map[string]any{"flicker": v.flicker}, true
	case module == "video" && name == "common":
		return map[string]any{"sensor_framerate": v.sensorFrameRate}, true
	default:
		return nil, false
	}
}

// write validates every module, section, leaf and value before changing either
// setting. Each section can be set independently, as in the real camera UI,
// or together in the recorder's observed enrollment request.
func (v *virtualImagingState) write(method string, request map[string]json.RawMessage) bool {
	if method != "set" || len(request) < 2 || len(request) > 3 {
		return false
	}
	var flicker, rate string
	for module, raw := range request {
		if module == "method" {
			continue
		}
		switch module {
		case "image":
			value, ok := imagingSetting(raw, "switch", "flicker")
			if !ok || (value != "50hz" && value != "60hz") {
				return false
			}
			flicker = value
		case "video":
			value, ok := imagingSetting(raw, "common", "sensor_framerate")
			if !ok || (value != "25" && value != "30") {
				return false
			}
			rate = value
		default:
			return false
		}
	}
	if flicker == "" && rate == "" {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if flicker != "" {
		v.flicker = flicker
	}
	if rate != "" {
		v.sensorFrameRate = rate
	}
	return true
}

func imagingSetting(raw json.RawMessage, section, leaf string) (string, bool) {
	var sections, fields map[string]json.RawMessage
	if json.Unmarshal(raw, &sections) != nil || len(sections) != 1 ||
		json.Unmarshal(sections[section], &fields) != nil || len(fields) != 1 {
		return "", false
	}
	var value string
	if json.Unmarshal(fields[leaf], &value) != nil {
		return "", false
	}
	return value, true
}
