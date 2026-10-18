package tpmarker

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const tagHex = "54504c494e4b4d41524b4552424f582e"

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The idle units are byte-for-byte the camera's (capture 2026-10-15): H.265
// suffix SEI 26 bytes, H.264 SEI 25 bytes, payload size 0x15 (21).
func TestIdleUnitsMatchCapturedCamera(t *testing.T) {
	h265, err := NAL("H265", State{})
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex(t, "50010515"+tagHex+"01000010"+"00"+"80"); !bytes.Equal(h265, want) || len(h265) != 26 {
		t.Fatalf("H.265 idle unit %x", h265)
	}
	h264, err := NAL("H264", State{})
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex(t, "060515"+tagHex+"01000010"+"00"+"80"); !bytes.Equal(h264, want) || len(h264) != 25 {
		t.Fatalf("H.264 idle unit %x", h264)
	}
}

// The alert records are copied from the camera's rule-alert units; the camera
// also sent box records alongside, which the translator cannot supply.
func TestIntrusionUnitCarriesCapturedAlertRecords(t *testing.T) {
	payload := Payload(State{IntrusionActive: true})
	want := mustHex(t, tagHex+"01000210"+"e0f101f101f000f000"+"070a0201010900ffff"+"00")
	if !bytes.Equal(payload, want) {
		t.Fatalf("payload %x", payload)
	}
	nal, err := NAL("H265", State{IntrusionActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if nal[0]>>1&63 != 40 || nal[2] != 5 || int(nal[3]) != len(payload) || nal[len(nal)-1] != 0x80 {
		t.Fatalf("H.265 alert NAL framing %x", nal)
	}
	if !bytes.Contains(nal, mustHex(t, "e0f101f101f000f000")) {
		t.Fatal("alert record missing from NAL")
	}
}

func TestEscapeInsertsEmulationPrevention(t *testing.T) {
	for _, tc := range []struct{ in, out string }{
		{"000001", "00000301"},
		{"00000000", "0000030000"},
		{"00000400", "00000400"},
		{"0000030000", "000003030000"},
		{"01000010", "01000010"},
	} {
		if got := escape(mustHex(t, tc.in)); !bytes.Equal(got, mustHex(t, tc.out)) {
			t.Fatalf("escape(%s) = %x, want %s", tc.in, got, tc.out)
		}
	}
	if _, err := NAL("MJPEG", State{}); err == nil {
		t.Fatal("unsupported codec accepted")
	}
}
