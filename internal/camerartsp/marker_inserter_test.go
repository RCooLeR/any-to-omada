package camerartsp

import (
	"bytes"
	"testing"

	"github.com/RCooLeR/any-to-omada/internal/tpmarker"
	"github.com/pion/rtp"
)

func TestMarkerInserterAppendsOneUnitPerAccessUnitAndRenumbers(t *testing.T) {
	active := false
	m := newMarkerInserter("H265", func() tpmarker.State { return tpmarker.State{IntrusionActive: active} })
	packet := func(seq uint16, ts uint32, marker bool) *rtp.Packet {
		return &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 96, SequenceNumber: seq, Timestamp: ts, SSRC: 7, Marker: marker}, Payload: []byte{0x02, 0x01, 0xaa}}
	}
	var out []*rtp.Packet
	input := []*rtp.Packet{packet(65534, 100, false), packet(65535, 100, true), packet(0, 3700, true)}
	out = append(out, m.process(input[0])...)
	out = append(out, m.process(input[1])...)
	active = true
	out = append(out, m.process(input[2])...)
	if len(out) != 5 {
		t.Fatalf("got %d packets", len(out))
	}
	for i, want := range []uint16{65534, 65535, 0, 1, 2} {
		if out[i].SequenceNumber != want {
			t.Fatalf("packet %d sequence %d, want %d", i, out[i].SequenceNumber, want)
		}
	}
	idle, _ := tpmarker.NAL("H265", tpmarker.State{})
	alert, _ := tpmarker.NAL("H265", tpmarker.State{IntrusionActive: true})
	if out[1].Marker || !out[2].Marker || out[2].Timestamp != 100 || out[2].SSRC != 7 || out[2].PayloadType != 96 || !bytes.Equal(out[2].Payload, idle) {
		t.Fatal("first access unit's marker unit is misplaced or wrong")
	}
	if out[3].Marker || !out[4].Marker || out[4].Timestamp != 3700 || !bytes.Equal(out[4].Payload, alert) {
		t.Fatal("second access unit did not carry the active intrusion unit")
	}
	if !input[1].Marker || input[2].SequenceNumber != 0 {
		t.Fatal("upstream packet was modified")
	}
	if newMarkerInserter("MJPEG", func() tpmarker.State { return tpmarker.State{} }) != nil || newMarkerInserter("H264", nil) != nil {
		t.Fatal("inserter created for an unsupported codec or without state")
	}
}
