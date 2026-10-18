package app

import (
	"encoding/json"
	"math"
	"strings"
	"unicode"
)

// SourceMetadata contains only source-reported identity and encoder settings.
// Empty strings, zero numbers and absent encoder indexes mean unknown.
type SourceMetadata struct {
	// Manufacturer is reported only by ISAPI and ONVIF sources.
	Manufacturer string
	Model        string
	Firmware     string
	BuildDate    string
	Encoders     map[int]SourceEncoders
}

// SourceEncoders maps the native source index to its first main and extra format.
type SourceEncoders struct {
	Main SourceEncoder
	Sub  SourceEncoder
}

// SourceEncoder is a reported configuration, not a list of supported options.
// Codec is H264, H265 or MJPEG; BitrateMode is CBR or VBR when recognized.
type SourceEncoder struct {
	Codec       string
	Width       int
	Height      int
	FPS         float64
	BitrateKbps int
	BitrateMode string
}

func (s *source) metadata() SourceMetadata {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := s.metadataValue
	result.Encoders = make(map[int]SourceEncoders, len(s.metadataValue.Encoders))
	for index, encoders := range s.metadataValue.Encoders {
		result.Encoders[index] = encoders
	}
	return result
}

func (s *source) recordMetadata(data any) {
	row, _ := data.(map[string]any)
	answer, _ := row["response"].(map[string]any)
	if answer["result"] != true {
		return
	}
	params, _ := answer["params"].(map[string]any)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch row["method"] {
	case "magicBox.getDeviceType":
		s.metadataValue.Model = metadataText(params["type"])
	case "magicBox.getSoftwareVersion":
		version, _ := params["version"].(map[string]any)
		s.metadataValue.Firmware = metadataText(version["Version"])
		s.metadataValue.BuildDate = metadataText(version["BuildDate"])
	case "configManager.getConfig":
		if row["configuration_name"] != "Encode" {
			return
		}
		table, ok := params["table"].([]any)
		if !ok {
			return
		}
		encoders := make(map[int]SourceEncoders)
		for index, entry := range table {
			lens, _ := entry.(map[string]any)
			main, sub := sourceEncoder(lens["MainFormat"]), sourceEncoder(lens["ExtraFormat"])
			if main != (SourceEncoder{}) || sub != (SourceEncoder{}) {
				encoders[index] = SourceEncoders{Main: main, Sub: sub}
			}
		}
		s.metadataValue.Encoders = encoders
	}
}

// recordIdentity stores the model and firmware an ISAPI or ONVIF adapter read.
// Encoder facts for these sources come from the active RTSP session.
func (s *source) recordIdentity(data any) {
	row, _ := data.(map[string]any)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.metadataValue.Manufacturer = metadataText(row["manufacturer"])
	s.metadataValue.Model = metadataText(row["model"])
	s.metadataValue.Firmware = metadataText(row["firmware"])
	s.metadataValue.BuildDate = metadataText(row["build_date"])
}

func sourceEncoder(value any) SourceEncoder {
	formats, ok := value.([]any)
	if !ok || len(formats) == 0 {
		return SourceEncoder{}
	}
	format, _ := formats[0].(map[string]any)
	video, _ := format["Video"].(map[string]any)
	result := SourceEncoder{
		Width: metadataInteger(video["Width"]), Height: metadataInteger(video["Height"]),
		FPS: metadataNumber(video["FPS"]), BitrateKbps: metadataInteger(video["BitRate"]),
	}
	switch video["Compression"] {
	case "H.264":
		result.Codec = "H264"
	case "H.265":
		result.Codec = "H265"
	case "MJPEG":
		result.Codec = "MJPEG"
	}
	switch video["BitRateControl"] {
	case "CBR":
		result.BitrateMode = "CBR"
	case "VBR":
		result.BitrateMode = "VBR"
	}
	return result
}

func metadataText(value any) string {
	text, ok := value.(string)
	if !ok || len(text) > 256 || strings.IndexFunc(text, unicode.IsControl) >= 0 {
		return ""
	}
	return strings.TrimSpace(text)
}

func metadataNumber(value any) float64 {
	number, ok := value.(json.Number)
	if !ok {
		return 0
	}
	parsed, err := number.Float64()
	if err != nil || parsed <= 0 || math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed > math.MaxInt32 {
		return 0
	}
	return parsed
}

func metadataInteger(value any) int {
	parsed := metadataNumber(value)
	if parsed != math.Trunc(parsed) {
		return 0
	}
	return int(parsed)
}
