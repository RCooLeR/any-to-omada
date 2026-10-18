package app

import (
	"encoding/json"
	"errors"
	"net"

	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

func decodeCallbackMessage(body json.RawMessage) (callbackMessage, error) {
	var message callbackMessage
	if err := json.Unmarshal(body, &message); err != nil {
		return callbackMessage{}, err
	}
	var status struct {
		ErrorCode *int `json:"error_code"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		return callbackMessage{}, err
	}
	if status.ErrorCode != nil {
		message.outerErrorPresent = true
		message.outerErrorCode = *status.ErrorCode
	}
	if message.Method == "" && status.ErrorCode != nil {
		// Actual recorder responses omit method entirely.
		message.Method = "response"
	}
	switch message.Method {
	case "declaration":
		var data struct {
			Version string `json:"version"`
		}
		if err := decodeCallbackData(message.RequestData, &data, "requestData"); err != nil {
			return callbackMessage{}, err
		}
		message.peerVersion = data.Version
	case "response":
		var data struct {
			ErrorCode   int `json:"error_code"`
			NotifyEvent *struct {
				ErrorCode *int `json:"error_code"`
			} `json:"notify_event"`
		}
		if len(message.ResponseData) > 0 {
			if err := decodeCallbackData(message.ResponseData, &data, "responseData"); err != nil {
				return callbackMessage{}, err
			}
		}
		message.responseCode = data.ErrorCode
		if message.outerErrorPresent && message.outerErrorCode != 0 {
			message.responseCode = message.outerErrorCode
		}
		if data.NotifyEvent != nil {
			message.notifyErrorCode = data.NotifyEvent.ErrorCode
		}
	case "passthrough", "auth":
		var data map[string]json.RawMessage
		if err := decodeCallbackData(message.RequestData, &data, "requestData"); err != nil {
			return callbackMessage{}, err
		}
		if data == nil {
			return callbackMessage{}, omadalink.ErrInvalidFrame
		}
	}
	return message, nil
}

func decodeCallbackData(raw json.RawMessage, target any, field string) error {
	if len(raw) == 0 {
		return omadalink.ErrInvalidFrame
	}
	if err := json.Unmarshal(raw, target); err != nil {
		var typeError *json.UnmarshalTypeError
		if errors.As(err, &typeError) {
			if typeError.Field != "" {
				field += "." + typeError.Field
			}
			typeError.Field = field
		}
		return err
	}
	return nil
}

func (c *callback) writePassthrough(conn net.Conn, message callbackMessage) string {
	request, err := omadalink.DecodePassthroughRequest(message.RequestData)
	if err != nil {
		c.logger.Warn("native passthrough request rejected", "message_id", message.ID)
		return "passthrough_request"
	}
	response := json.RawMessage(`{"error_code":-40106}`)
	if c.passthrough != nil {
		response = c.passthrough(request)
	}
	frame, err := omadalink.EncodePassthroughResponse(message.ID, response)
	if err != nil {
		c.logger.Warn("native passthrough response rejected", "message_id", message.ID)
		return "passthrough_response"
	}
	if err := writeCallback(conn, frame); err != nil {
		return "passthrough_write"
	}
	c.logger.Info("native passthrough response written", "message_id", message.ID)
	return ""
}
