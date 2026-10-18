package omadalink

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// MaxPostTLSFrameSize leaves room for the terminating NUL in the observed
	// camera's 1024-byte output buffer. Oversized messages are never truncated.
	MaxPostTLSFrameSize = 1023
	// FirstMessageID starts the camera-owned counter after each TLS connection.
	FirstMessageID uint16 = 32768
)

// EventType is a donor firmware event number, not an ONVIF topic or Dahua code.
// These labels come from the firmware's indexed event table. Their presence does
// not establish feature availability on a camera or acceptance by an NVR.
type EventType uint16

const (
	EventMotion           EventType = 2
	EventTamper           EventType = 3
	EventLineCrossing     EventType = 4
	EventIntrusion        EventType = 5
	EventHuman            EventType = 26
	EventVehicle          EventType = 27
	EventHumanMotion      EventType = 32
	EventVehicleMotion    EventType = 33
	EventHumanIntrusion   EventType = 34
	EventVehicleIntrusion EventType = 35
	EventHumanLine        EventType = 36
	EventVehicleLine      EventType = 37
	EventPet              EventType = 75
	EventPetMotion        EventType = 80
	EventPetLine          EventType = 81
	EventPetIntrusion     EventType = 82
)

// Event describes one already-mapped alarm. Status is the wire value 1, 2 or 3;
// firmware input states 1/3 become 1, 4/5 become 2 and 0 becomes 3. Immediate
// firmware state 2 is unsupported. Callers must establish their source mapping.
// RegionID zero omits region_id. No timestamp, channel or object geometry is
// synthesized: none occurs in this donor's ordinary alarm envelope.
type Event struct {
	Type     EventType `json:"event_type"`
	Status   uint8     `json:"event_status"`
	RegionID uint32    `json:"region_id,omitempty"`
}

// DeclarationIdentity contains the virtual camera's own identity. Callers must
// supply its advertised IPv4 address, MAC and name, never another device's identity.
type DeclarationIdentity struct {
	IP   netip.Addr
	MAC  [6]byte
	Name string
}

// NextMessageID advances a camera-owned counter, wrapping 65535 to 32768.
// Values below FirstMessageID are invalid; a new connection starts there instead.
func NextMessageID(current uint16) (uint16, error) {
	if current < FirstMessageID {
		return 0, ErrInvalidFrame
	}
	if current == 65535 {
		return FirstMessageID, nil
	}
	return current + 1, nil
}

// EncodeEvent encodes one ordinary post-TLS alarm using the firmware's literal
// Content-Type typo, Nofity_Event. It performs no I/O or authentication and must
// only be sent by a separately authenticated connection. Special event bitmap
// types 65533/65535 and any event-to-source mapping are deliberately unsupported.
func EncodeEvent(id uint16, event Event) ([]byte, error) {
	if event.Type > 82 || event.Status < 1 || event.Status > 3 || event.RegionID > 0x7fffffff {
		return nil, ErrInvalidFrame
	}
	message := struct {
		ID          uint16 `json:"id"`
		Method      string `json:"method"`
		RequestData struct {
			Events [1]Event `json:"notify_event"`
		} `json:"requestData"`
	}{ID: id, Method: "notify"}
	message.RequestData.Events[0] = event
	return encodePostTLS(id, "Nofity_Event", message)
}

// EncodeHeartbeat encodes the observed camera heartbeat request. It does not
// start a timer, track replies or infer that the recorder accepted a connection.
func EncodeHeartbeat(id uint16) ([]byte, error) {
	return encodePostTLS(id, "Request", struct {
		ID     uint16 `json:"id"`
		Method string `json:"method"`
	}{ID: id, Method: "heartbeat"})
}

// EncodeDeclaration encodes the local-camera declaration sent after TLS succeeds.
// The fixed version describes this observed message format, not implemented
// camera capabilities. No handshake, recorder registration or runtime state changes.
func EncodeDeclaration(id uint16, identity DeclarationIdentity) ([]byte, error) {
	if !identity.IP.Is4() || identity.IP.IsUnspecified() || identity.IP.IsMulticast() ||
		identity.Name == "" || len(identity.Name) > MaxPostTLSFrameSize || !utf8.ValidString(identity.Name) ||
		strings.Contains(identity.Name, "--start-boundary--") || strings.Contains(identity.Name, "--end-boundary--") {
		return nil, ErrInvalidFrame
	}
	message := struct {
		ID          uint16 `json:"id"`
		Method      string `json:"method"`
		RequestData struct {
			IP         string `json:"ip"`
			MAC        string `json:"mac"`
			Name       string `json:"dev_name"`
			RemoteFlag int    `json:"remote_flag"`
			MsgVersion int    `json:"msg_version"`
			Version    string `json:"version"`
		} `json:"requestData"`
	}{ID: id, Method: "declaration"}
	message.RequestData.IP = identity.IP.String()
	message.RequestData.MAC = fmt.Sprintf("%02X-%02X-%02X-%02X-%02X-%02X",
		identity.MAC[0], identity.MAC[1], identity.MAC[2], identity.MAC[3], identity.MAC[4], identity.MAC[5])
	message.RequestData.Name = identity.Name
	message.RequestData.MsgVersion = 1
	message.RequestData.Version = "0101000101"
	return encodePostTLS(id, "Declaration", message)
}

func encodePostTLS(id uint16, contentType string, message any) ([]byte, error) {
	if id < FirstMessageID {
		return nil, ErrInvalidFrame
	}
	body, err := json.Marshal(message)
	if err != nil {
		return nil, ErrInvalidFrame
	}
	// This differs from the pre-TLS envelope's formatting: no spaces after the
	// colons, no blank line before JSON, and no CRLF after the end boundary.
	header := startBoundary + "Content-Type:" + contentType + "\r\nContent-Length:" + strconv.Itoa(len(body)) + "\r\n"
	if len(header)+len(body)+len(endBoundary) > MaxPostTLSFrameSize {
		return nil, ErrFrameTooLarge
	}
	encoded := make([]byte, 0, len(header)+len(body)+len(endBoundary))
	encoded = append(encoded, header...)
	encoded = append(encoded, body...)
	return append(encoded, endBoundary...), nil
}
