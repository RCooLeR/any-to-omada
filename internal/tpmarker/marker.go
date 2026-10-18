// Package tpmarker encodes the per-frame smart metadata unit that native Omada
// cameras carry inside their video stream: an SEI "user data unregistered"
// message whose 16-byte identifier is the ASCII tag TPLINKMARKERBOX.
//
// Layout observed from an Omada 8MP Turret (2026-10-15 capture, every frame of
// both the H.265 main and the H.264 sub stream):
//
//	tag[16] | 0x01 | box count | item count | 0x10 | records (9 bytes each) | 0x00
//
// Box records (0x01 motion, 0x04 human, ...) hold four big-endian coordinates
// on a 0-10000 grid. A rule alert is record 0xe0 followed by its companion
// record 0x07; idle frames carry the 21-byte unit without records.
package tpmarker

import (
	"errors"
)

// Tag is the SEI user-data identifier used by the camera.
const Tag = "TPLINKMARKERBOX."

const (
	seiUserDataUnregistered = 5
	h265SuffixSEI           = 40
	h264SEI                 = 6
)

var (
	// intrusionAlert reports the first rule block (intrusion) active for target
	// bitmap 1 and region bitmap 1, with the line-crossing block inactive.
	intrusionAlert = []byte{0xe0, 0xf1, 0x01, 0xf1, 0x01, 0xf0, 0x00, 0xf0, 0x00}
	// alertCompanion always followed the rule alert in the capture. Its fields
	// are not decoded; it is reproduced verbatim.
	alertCompanion = []byte{0x07, 0x0a, 0x02, 0x01, 0x01, 0x09, 0x00, 0xff, 0xff}
)

// State selects the content of one frame's unit.
type State struct {
	// IntrusionActive adds the intrusion rule alert. No target box is added:
	// the translator's sources do not report one.
	IntrusionActive bool
}

// Payload returns the SEI user-data payload (identifier, header, records and
// trailer) for one frame.
func Payload(state State) []byte {
	items := byte(0)
	records := []byte{}
	if state.IntrusionActive {
		records = append(records, intrusionAlert...)
		records = append(records, alertCompanion...)
		items = 2
	}
	payload := make([]byte, 0, len(Tag)+4+len(records)+1)
	payload = append(payload, Tag...)
	payload = append(payload, 0x01, 0x00, items, 0x10)
	payload = append(payload, records...)
	return append(payload, 0x00)
}

// NAL returns the complete SEI NAL unit for codec "H264" or "H265", with
// emulation prevention applied, ready for a single-NAL-unit RTP packet. H.265
// uses a suffix SEI (type 40, temporal id 0) like the camera.
func NAL(codec string, state State) ([]byte, error) {
	payload := Payload(state)
	rbsp := []byte{seiUserDataUnregistered}
	for size := len(payload); ; size -= 255 {
		if size < 255 {
			rbsp = append(rbsp, byte(size))
			break
		}
		rbsp = append(rbsp, 0xff)
	}
	rbsp = append(rbsp, payload...)
	rbsp = append(rbsp, 0x80) // rbsp_trailing_bits
	var header []byte
	switch codec {
	case "H265":
		header = []byte{h265SuffixSEI << 1, 0x01}
	case "H264":
		header = []byte{h264SEI}
	default:
		return nil, errors.New("tpmarker: unsupported codec")
	}
	return append(header, escape(rbsp)...), nil
}

// escape inserts emulation prevention bytes: any 0x00 0x00 followed by a byte
// of 0x03 or less gets 0x03 inserted before that byte.
func escape(rbsp []byte) []byte {
	out := make([]byte, 0, len(rbsp)+len(rbsp)/32+2)
	zeros := 0
	for _, b := range rbsp {
		if zeros >= 2 && b <= 3 {
			out = append(out, 3)
			zeros = 0
		}
		out = append(out, b)
		if b == 0 {
			zeros++
		} else {
			zeros = 0
		}
	}
	return out
}
