package camerartsp

import (
	"sync"

	"github.com/RCooLeR/any-to-omada/internal/tpmarker"
	"github.com/pion/rtp"
)

// markerInserter adds one TP-Link marker SEI packet to every video access unit
// of a forwarded stream, as native Omada cameras do: a single-NAL-unit packet
// with the access unit's timestamp, placed after its last packet and carrying
// the RTP marker bit. Forwarded packets are renumbered so the outgoing
// sequence stays contiguous. One inserter belongs to one media of one upstream
// generation.
type markerInserter struct {
	codec string
	state func() tpmarker.State
	// mu guards offset; packet callbacks may run on library goroutines.
	mu     sync.Mutex
	offset uint16
}

// newMarkerInserter returns nil when markers are disabled or the codec cannot
// carry the supported H.264/H.265 marker units.
func newMarkerInserter(codec string, state func() tpmarker.State) *markerInserter {
	if state == nil || (codec != "H264" && codec != "H265") {
		return nil
	}
	return &markerInserter{codec: codec, state: state}
}

// process returns the packets to forward for one upstream packet. The input is
// not modified. Access units are delimited by the marker bit; a source that
// never sets it gets no units.
func (m *markerInserter) process(packet *rtp.Packet) []*rtp.Packet {
	m.mu.Lock()
	defer m.mu.Unlock()
	forwarded := &rtp.Packet{Header: packet.Header, Payload: packet.Payload, PaddingSize: packet.PaddingSize}
	forwarded.Header.CSRC = append([]uint32(nil), packet.Header.CSRC...)
	forwarded.Header.Extensions = append([]rtp.Extension(nil), packet.Header.Extensions...)
	forwarded.SequenceNumber = packet.SequenceNumber + m.offset
	if !packet.Marker {
		return []*rtp.Packet{forwarded}
	}
	nal, err := tpmarker.NAL(m.codec, m.state())
	if err != nil {
		return []*rtp.Packet{forwarded}
	}
	forwarded.Marker = false
	unit := &rtp.Packet{Header: rtp.Header{Version: 2, Marker: true, PayloadType: packet.PayloadType,
		SequenceNumber: forwarded.SequenceNumber + 1, Timestamp: packet.Timestamp, SSRC: packet.SSRC}, Payload: nal}
	m.offset++
	return []*rtp.Packet{forwarded, unit}
}
