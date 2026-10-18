package omadalink

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

func TestPostTLSSyntheticWireFixtures(t *testing.T) {
	for _, test := range []struct {
		name   string
		encode func() ([]byte, error)
		wire   string
	}{
		{
			name:   "heartbeat",
			encode: func() ([]byte, error) { return EncodeHeartbeat(32768) },
			wire:   "--start-boundary--\r\nContent-Type:Request\r\nContent-Length:33\r\n" + `{"id":32768,"method":"heartbeat"}` + "\r\n--end-boundary--",
		},
		{
			name: "human motion",
			encode: func() ([]byte, error) {
				return EncodeEvent(32769, Event{Type: EventHumanMotion, Status: 1})
			},
			wire: "--start-boundary--\r\nContent-Type:Nofity_Event\r\nContent-Length:98\r\n" + `{"id":32769,"method":"notify","requestData":{"notify_event":[{"event_type":32,"event_status":1}]}}` + "\r\n--end-boundary--",
		},
		{
			name: "tamper stop",
			encode: func() ([]byte, error) {
				return EncodeEvent(32771, Event{Type: EventTamper, Status: 3})
			},
			wire: "--start-boundary--\r\nContent-Type:Nofity_Event\r\nContent-Length:97\r\n" + `{"id":32771,"method":"notify","requestData":{"notify_event":[{"event_type":3,"event_status":3}]}}` + "\r\n--end-boundary--",
		},
		{
			name: "intrusion region end",
			encode: func() ([]byte, error) {
				return EncodeEvent(32770, Event{Type: EventHumanIntrusion, Status: 2, RegionID: 4})
			},
			wire: "--start-boundary--\r\nContent-Type:Nofity_Event\r\nContent-Length:112\r\n" + `{"id":32770,"method":"notify","requestData":{"notify_event":[{"event_type":34,"event_status":2,"region_id":4}]}}` + "\r\n--end-boundary--",
		},
		{
			name:   "local declaration",
			encode: func() ([]byte, error) { return EncodeDeclaration(32768, syntheticIdentity()) },
			wire:   "--start-boundary--\r\nContent-Type:Declaration\r\nContent-Length:180\r\n" + `{"id":32768,"method":"declaration","requestData":{"ip":"192.0.2.21","mac":"02-00-00-00-00-21","dev_name":"Synthetic camera","remote_flag":0,"msg_version":1,"version":"0101000101"}}` + "\r\n--end-boundary--",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire, err := test.encode()
			if err != nil || string(wire) != test.wire {
				t.Fatalf("post-TLS bytes differ from synthetic firmware-format fixture: %v", err)
			}
			// Receiving a post-TLS type must not broaden the pre-TLS state machine.
			if _, err := ReadFrame(bufio.NewReader(bytes.NewReader(wire)), false); !errors.Is(err, ErrInvalidFrame) {
				t.Fatalf("handshake decoder accepted a post-TLS envelope: %v", err)
			}
		})
	}
}

func TestPostTLSByteLengthsAndMaximum(t *testing.T) {
	identity := syntheticIdentity()
	identity.Name = "Synthetic \u043a\u0430\u043c\u0435\u0440\u0430 \"test\""
	wire, err := EncodeDeclaration(32768, identity)
	if err != nil {
		t.Fatal(err)
	}
	parts := bytes.SplitN(wire, []byte("\r\n"), 4)
	length, err := strconv.Atoi(strings.TrimPrefix(string(parts[2]), "Content-Length:"))
	body := bytes.TrimSuffix(parts[3], []byte(endBoundary))
	if err != nil || length != len(body) || !json.Valid(body) || !bytes.Contains(body, []byte("\u043a\u0430\u043c\u0435\u0440\u0430")) {
		t.Fatalf("UTF-8 payload length or JSON escaping is wrong: %v", err)
	}

	identity.Name = strings.Repeat("x", 512)
	wire, err = EncodeDeclaration(32768, identity)
	if err != nil {
		t.Fatal(err)
	}
	identity.Name += strings.Repeat("x", MaxPostTLSFrameSize-len(wire))
	wire, err = EncodeDeclaration(32768, identity)
	if err != nil || len(wire) != MaxPostTLSFrameSize {
		t.Fatalf("exact post-TLS frame bound failed: size=%d error=%v", len(wire), err)
	}
	identity.Name += "x"
	if wire, err = EncodeDeclaration(32768, identity); !errors.Is(err, ErrFrameTooLarge) || wire != nil {
		t.Fatalf("oversized declaration was emitted or truncated: %v", err)
	}
}

func TestPostTLSInvalidInputsAreRejectedWithoutPayload(t *testing.T) {
	for _, event := range []Event{
		{Type: 83, Status: 1},
		{Type: 65533, Status: 1},
		{Type: 65535, Status: 1},
		{Type: EventMotion, Status: 0},
		{Type: EventMotion, Status: 4},
		{Type: EventMotion, Status: 1, RegionID: 0x80000000},
	} {
		if wire, err := EncodeEvent(32768, event); wire != nil || !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("unsupported event accepted: %v", err)
		}
	}
	for _, id := range []uint16{0, 1, 32767} {
		for _, encode := range []func() ([]byte, error){
			func() ([]byte, error) { return EncodeHeartbeat(id) },
			func() ([]byte, error) { return EncodeEvent(id, Event{Type: EventMotion, Status: 1}) },
			func() ([]byte, error) { return EncodeDeclaration(id, syntheticIdentity()) },
		} {
			if wire, err := encode(); wire != nil || !errors.Is(err, ErrInvalidFrame) {
				t.Fatalf("non-camera message ID accepted: %v", err)
			}
		}
	}
	for _, name := range []string{"", "synthetic-private--end-boundary--", "synthetic-private--start-boundary--", "\xff", strings.Repeat("x", 1024)} {
		identity := syntheticIdentity()
		identity.Name = name
		if wire, err := EncodeDeclaration(32768, identity); wire != nil || !errors.Is(err, ErrInvalidFrame) || strings.Contains(err.Error(), "synthetic-private") {
			t.Fatalf("unsafe declaration accepted or reflected into an error: %v", err)
		}
	}
	for _, ip := range []netip.Addr{{}, netip.IPv6Loopback(), netip.IPv4Unspecified(), netip.MustParseAddr("239.0.0.1")} {
		identity := syntheticIdentity()
		identity.IP = ip
		if _, err := EncodeDeclaration(32768, identity); !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("non-unicast IPv4 identity accepted: %v", err)
		}
	}
}

func TestPostTLSCounterWrapAndNoImplicitState(t *testing.T) {
	for _, test := range []struct{ current, next uint16 }{{32768, 32769}, {65534, 65535}, {65535, 32768}} {
		got, err := NextMessageID(test.current)
		if err != nil || got != test.next {
			t.Fatalf("camera ID sequence failed at %d: got=%d error=%v", test.current, got, err)
		}
	}
	if _, err := NextMessageID(32767); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("invalid counter accepted: %v", err)
	}
	first, err := EncodeHeartbeat(FirstMessageID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncodeHeartbeat(FirstMessageID)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("pure encoder unexpectedly advanced state: %v", err)
	}
}

func syntheticIdentity() DeclarationIdentity {
	return DeclarationIdentity{
		IP:   netip.MustParseAddr("192.0.2.21"),
		MAC:  [6]byte{0x02, 0, 0, 0, 0, 0x21},
		Name: "Synthetic camera",
	}
}
