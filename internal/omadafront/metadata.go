package omadafront

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
)

// Metadata keeps source-camera facts separate from the translator identity.
// Video is keyed by the management profile names main and minor.
type Metadata struct {
	Name, Brand, Model, Firmware, BuildDate, SoftwareVersion string
	Video                                                    map[string]VideoMetadata
}

// VideoMetadata reports the selected source encoding, never donor capabilities.
// Zero numeric fields and empty strings mean unknown and are omitted on the wire.
type VideoMetadata struct {
	Codec                                    string
	Width, Height, BitrateKbps               int
	FrameRateNumerator, FrameRateDenominator uint32
	BitrateMode                              string
}

// selectorNames normalizes a scalar selector or bounded nonempty selector
// list, rejecting names over 128 bytes.
func selectorNames(raw json.RawMessage) ([]string, bool) {
	var name string
	if json.Unmarshal(raw, &name) == nil && name != "" && len(name) <= 128 {
		return []string{name}, true
	}
	var names []string
	if json.Unmarshal(raw, &names) != nil || len(names) == 0 || len(names) > 32 {
		return nil, false
	}
	for _, name := range names {
		if name == "" || len(name) > 128 {
			return nil, false
		}
	}
	return names, true
}

// readSection resolves supported management leaves from source facts or
// virtual state; optional PTZ capability discovery can contact the source.
func (s *Server) readSection(module, name string, metadata Metadata) (any, bool) {
	if len(s.illuminationCapability().Modes) > 0 && module == "image" && (name == "switch" || name == "common") {
		return s.illuminationRead(module, name)
	}
	if fields, supported := s.illuminationRead(module, name); supported {
		return fields, true
	}
	if fields, supported := s.outputRead(module, name); supported {
		return fields, true
	}
	switch {
	case module == "function" && name == "module_spec":
		spec := map[string]any{"preview": []string{"local"}, "network": []string{"ethernet"},
			"video_codec": []string{"h264", "h265"}, "stream_max_sessions": "8",
			"omada_ipc": "1.0", "nvr_long_connect": callbackVersionCapability(s.startCallback != nil), "smart_detection": "0", "msg_push": "0", "smart_msg_push_capability": "0", "local_storage": "0"}
		if s.compat.ObservedModuleSpec {
			spec = observedModuleSpec(callbackVersionCapability(s.startCallback != nil))
		}
		if s.ptz != nil {
			// Experimental: candidate keys that may make the recorder offer
			// PTZ controls. Only advertised while a PTZ controller exists.
			for _, key := range s.compat.PTZModuleSpecKeys {
				spec[key] = "1"
			}
		}
		s.outputModuleSpec(spec)
		s.illuminationModuleSpec(spec)
		return spec, true
	case module == "ptz" && name == "capability" && s.ptz != nil:
		ctx, cancel := context.WithTimeout(context.Background(), ptzCallTimeout)
		defer cancel()
		return s.nativePTZCapabilityFields(ctx)
	case module == "network" && name == "wan_status":
		// This describes the reachable virtual management interface, not the
		// source camera's physical link or its unobserved network settings.
		wan := map[string]any{"ipaddr": s.ip, "proto": "static", "up_time": int64(s.now().Sub(s.started).Seconds()), "error_code": 0,
			"link_status": 1, "phy_status": 1}
		if s.mac != "" {
			wan["mac"] = s.mac
		}
		s.compat.extendWANStatus(wan)
		return wan, true
	case module == "system" && (name == "time_status" || name == "basic" || name == "dst_manual"):
		return s.virtualTime.read(name)
	case module == "device_info" && (name == "basic_info" || name == "info") && metadata.SoftwareVersion != "":
		return s.deviceInfo(name, metadata), true
	case module == "video" && (name == "main" || name == "minor"):
		profile, ok := metadata.Video[name]
		if !ok || (profile.Codec != "H264" && profile.Codec != "H265") || profile.Width <= 0 || profile.Height <= 0 {
			return nil, false
		}
		fields := profile.fields()
		fields["name"] = "VideoEncoder_1"
		if name == "minor" {
			fields["name"] = "VideoEncoder_2"
		}
		// Omada's UI defines 1/3/5 as low/medium/high. This is the virtual
		// medium quality preference, not a conversion of the source encoder's
		// different quality scale. Actual source codec/rate/geometry stay above.
		fields["quality"] = "3"
		s.compat.extendVideoFields(name, fields)
		return fields, true
	case (module == "image" && name == "switch") || (module == "video" && name == "common"):
		return s.virtualImaging.read(module, name)
	case module == "motion_detection" || module == "tamper_detection" || module == "intrusion_detection" || module == "linecrossing_detection" || module == "marker_box":
		return s.virtualDetect.read(module, name)
	case module == "smart_detection" && name == "capability":
		return smartDetectionCapability(s.compat.ObservedModuleSpec), true
	case module == "ai_enhance_capability" && name == "traditional_enhance" && s.compat.ObservedModuleSpec:
		// Experimental, observed profile only: the Omada camera's people,
		// vehicle and pet enhancement versions. Answering this, linkage and
		// smart_data made the recorder store human intrusions (2026-10-16).
		return map[string]any{"people_enhance_ver": "7", "vehicle_enhance_ver": "7", "pet_enhance_ver": "7"}, true
	case module == "linkage_capability" && name == "capability" && s.compat.ObservedModuleSpec:
		// Experimental, observed profile only: the Omada camera's per-event
		// linkage bit strings (bit positions undecoded).
		return observedLinkageCapability(), true
	case module == "cet" && name == "rtsp":
		// This is the recorder-facing port, not the NAT backend. Only advertise
		// the MD5 challenge when the caller has enabled it on the RTSP listener.
		fields := map[string]any{"port": "554"}
		if s.rtspDigest {
			fields["digest_auth_type"] = "MD5"
		}
		return fields, true
	case module == "cet" && name == "vhttpd" && s.compat.AdvertiseVHTTPD:
		// Experimental: the donor reports this service; no translator listener exists.
		fields := map[string]any{"port": "8800"}
		if s.rtspDigest {
			fields["digest_auth_type"] = "MD5"
		}
		return fields, true
	case module == "upnpc" && name == "upnpc_info":
		return map[string]any{"enabled": "off", "mode": "manual"}, true
	default:
		return nil, false
	}
}

// upnpServiceStatus describes advertised virtual services as unmapped, using
// recorder-facing addresses and ports rather than backend listener addresses.
func (s *Server) upnpServiceStatus() []any {
	// The donor reports known services even when no UPnP mapping exists.
	// Describe only the implemented virtual listeners, using recorder-facing
	// ports and the virtual IP rather than NAT backends or donor endpoints.
	services := s.compat.services()
	rows := make([]any, 0, len(services))
	for _, service := range services {
		rows = append(rows, map[string]any{service.name: map[string]any{
			"ext_port": service.port, "inner_port": service.port, "ipaddr": s.ip, "status": "off",
		}})
	}
	return rows
}

// deviceInfo combines source model/firmware facts with the translator identity
// and optional virtual compatibility fields without borrowing a donor identity.
func (s *Server) deviceInfo(name string, metadata Metadata) map[string]any {
	model := "AnyToOmada"
	if metadata.Model != "" {
		model = strings.TrimSpace(metadata.Brand+" "+metadata.Model) + " · AnyToOmada"
	}
	firmware := "translator " + metadata.SoftwareVersion
	if metadata.Firmware != "" {
		firmware = strings.TrimSpace(metadata.Firmware+" "+metadata.BuildDate) + " · " + firmware
	}
	manufacturer := "AnyToOmada"
	if s.compat.ManufacturerName != "" {
		manufacturer = s.compat.ManufacturerName
	}
	body := map[string]any{"device_model": model, "sw_version": firmware, "device_name": metadata.Name, "manufacturer_name": manufacturer}
	if name == "basic_info" {
		body["device_type"] = "SECUR.CONSUMER.IPC"
		body["device_alias"] = metadata.Name
		if s.mac != "" {
			body["mac"] = s.mac
		}
	} else {
		body["model_description"] = model
		body["up_time"] = int64(s.now().Sub(s.started).Seconds())
	}
	s.compat.extendIdentity(name, body, metadata.Name)
	return body
}

// fields converts source encoding facts to Omada leaves after the caller validates
// the codec and positive dimensions. Unknown optional values and unsupported
// fractional frame-rate representations are omitted.
func (p VideoMetadata) fields() map[string]any {
	body := map[string]any{"encode_type": p.Codec, "resolution": strconv.Itoa(p.Width) + "*" + strconv.Itoa(p.Height)}
	if p.BitrateKbps > 0 {
		body["bitrate"] = strconv.Itoa(p.BitrateKbps)
	}
	if p.BitrateMode == "cbr" || p.BitrateMode == "vbr" {
		body["bitrate_type"] = p.BitrateMode
	}
	// The shipped Omada UI decodes integer rates by subtracting 65536.
	// Fractional-rate encoding has not been established; omit it rather than
	// inventing a packed-rational representation.
	if p.FrameRateDenominator > 0 && p.FrameRateNumerator%p.FrameRateDenominator == 0 {
		fps := p.FrameRateNumerator / p.FrameRateDenominator
		if fps > 0 && fps <= 240 {
			body["frame_rate"] = strconv.FormatUint(uint64(65536+fps), 10)
		}
	}
	return body
}
