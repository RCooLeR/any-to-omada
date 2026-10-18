package omadafront

import (
	"context"
	"encoding/json"
)

// Passthrough dispatches an already URL-decoded management object received over
// the authenticated native recorder callback. It creates no HTTP session.
// Image flicker, detection and time writes change virtual state only; explicitly
// configured PTZ, output and illumination delegates can control sources. The caller
// must complete callback authentication before using this entry point.
func (s *Server) Passthrough(raw json.RawMessage) json.RawMessage {
	response := map[string]any{"error_code": unsupportedCode}
	var request map[string]json.RawMessage
	var method string
	valid := len(raw) <= maxBodyBytes && json.Unmarshal(raw, &request) == nil && request != nil &&
		json.Unmarshal(request["method"], &method) == nil
	s.mu.Lock()
	s.status.Requests++
	s.mu.Unlock()
	outputHandled := false
	illuminationHandled := false
	if valid {
		if value, ok := s.illuminationRequest(context.Background(), method, request); ok {
			response, illuminationHandled = value, true
		} else if value, ok := s.outputRequest(context.Background(), method, request); ok {
			response, outputHandled = value, true
		}
	}
	ptzHandled := false
	if valid && !outputHandled && !illuminationHandled && s.ptz != nil && isPTZRequest(request) {
		response, ptzHandled = s.ptzRequest(context.Background(), method, request)
		if !ptzHandled {
			response = map[string]any{"error_code": unsupportedCode}
		}
	}
	if valid && !ptzHandled && !outputHandled && !illuminationHandled {
		if method == "get" {
			if value, ok := s.read(request); ok {
				response = value
			}
		} else if method == "do" && len(request) == 2 && emptyJSONObject(request["get_rtsp_info"]) {
			response = s.streamDiscovery()
		} else if s.virtualTime.write(method, request) || s.virtualImaging.write(method, request) || s.virtualDetect.write(method, request) {
			response = map[string]any{"error_code": 0}
		}
	}
	code, _ := response["error_code"].(int)
	if code != 0 {
		s.unsupported(request, method)
	}
	if s.logger != nil {
		operation := "invalid"
		if valid {
			operation = operationLabel(request, method)
			if method == "get" && code == 0 {
				operation = successfulReadLabel(request)
			}
			if ptzHandled {
				operation = "ptz_control"
			}
			if outputHandled {
				operation = "output_control"
			}
			if illuminationHandled {
				operation = "illumination_control"
			}
		}
		fields := []any{"operation", operation, "error_code", code}
		if valid && (code != 0 || ptzHandled || outputHandled || illuminationHandled) {
			fields = append(fields, "request_shape", requestShape(request))
		}
		if valid && method == "get" {
			selectors, forms, unknown := readSelectorLabels(request)
			fields = append(fields, "read_modules", readModuleLabels(request), "read_selectors", selectors,
				"read_selector_forms", forms, "unknown_read_modules", unknown)
		} else if valid && (method == "set" || method == "do") {
			fields = append(fields, "write_operations", writeOperationLabels(request))
		}
		s.logger.Info("native management request", fields...)
	}
	// Responses contain only the same built-in JSON values as the HTTP handler.
	encoded, err := json.Marshal(response)
	if err != nil {
		return json.RawMessage(`{"error_code":-40106}`)
	}
	return encoded
}
