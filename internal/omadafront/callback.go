package omadafront

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
)

// callbackVersionCapability advertises native callback version 1.0 only when
// the application supplies a callback worker.
func callbackVersionCapability(value bool) string {
	if value {
		return "1.0"
	}
	return "0"
}

// callback validates and dispatches one native callback start/stop request.
// A true return means an HTTP response was written, not that enrollment succeeded.
func (s *Server) callback(w http.ResponseWriter, request map[string]json.RawMessage) bool {
	if s.startCallback == nil || len(request) != 2 {
		return false
	}
	var operations map[string]json.RawMessage
	if json.Unmarshal(request["nvr_long_connect"], &operations) != nil || len(operations) != 1 {
		return false
	}
	if raw, found := operations["nvr_connect_stop"]; found && s.stopCallback != nil {
		var stop struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&stop)
		ip, ipErr := netip.ParseAddr(stop.IP)
		if err != nil || ipErr != nil || !ip.Is4() || stop.Port < 1 || stop.Port > 65535 {
			s.write(w, http.StatusOK, map[string]any{"error_code": -40211})
			return true
		}
		s.stopCallback(stop.IP, stop.Port)
		s.write(w, http.StatusOK, map[string]any{"error_code": 0})
		return true
	}
	raw, found := operations["nvr_connect_start"]
	if !found {
		return false
	}
	var registration CallbackRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&registration)
	ip, ipErr := netip.ParseAddr(registration.IP)
	if err != nil || ipErr != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() ||
		registration.IP == "255.255.255.255" || registration.Port < 1 || registration.Port > 65535 ||
		registration.Version != "0101000101" || len(registration.AuthCode) == 0 || len(registration.AuthCode) > 64 ||
		strings.IndexByte(registration.AuthCode, 0) >= 0 {
		s.write(w, http.StatusOK, map[string]any{"error_code": unsupportedCode})
		return true
	}
	if s.startCallback(registration) != nil {
		s.write(w, http.StatusOK, map[string]any{"error_code": unsupportedCode})
		return true
	}
	// Acceptance starts the real callback worker. It does not claim that the
	// subsequent authentication, declaration or recorder enrollment has passed.
	s.write(w, http.StatusOK, map[string]any{"version": "0101000101", "error_code": 0})
	return true
}
