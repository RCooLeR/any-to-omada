package camerartsp

import (
	"bytes"
	"math"
	"testing"

	"github.com/bluenviron/gortsplib/v5"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
	"github.com/bluenviron/gortsplib/v5/pkg/description"
	"github.com/bluenviron/gortsplib/v5/pkg/format"
)

var metadataH264SPS = []byte{
	0x67, 0x64, 0x00, 0x0c, 0xac, 0x3b, 0x50, 0xb0, 0x4b, 0x42,
	0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x03, 0x00, 0x3d, 0x08,
}

var metadataH265SPS = []byte{
	0x42, 0x01, 0x01, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x90,
	0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x78, 0xa0, 0x03,
	0xc0, 0x80, 0x10, 0xe5, 0x96, 0x66, 0x69, 0x24, 0xca, 0xe0,
	0x10, 0x00, 0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x03, 0x01, 0xe0, 0x80,
}

func TestDescriptionVideoMetadata(t *testing.T) {
	for _, tc := range []struct {
		name  string
		video format.Format
		want  VideoMetadata
	}{
		{"h264", &format.H264{SPS: metadataH264SPS}, VideoMetadata{Codec: "H264", Width: 352, Height: 288, FrameRateNumerator: 15, FrameRateDenominator: 1}},
		{"h265", &format.H265{SPS: metadataH265SPS}, VideoMetadata{Codec: "H265", Width: 1920, Height: 1080, FrameRateNumerator: 30, FrameRateDenominator: 1}},
		{"missing SPS", &format.H264{}, VideoMetadata{Codec: "H264"}},
		{"malformed SPS", &format.H265{SPS: []byte{0x42, 1, 1}}, VideoMetadata{Codec: "H265"}},
		{"oversized SPS", &format.H264{SPS: bytes.Repeat([]byte{0x67}, 4097)}, VideoMetadata{Codec: "H264"}},
		{"unsupported codec", &format.MJPEG{}, VideoMetadata{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			desc := &description.Session{Medias: []*description.Media{
				{Type: description.MediaTypeAudio, Formats: []format.Format{&format.G711{}}},
				{Type: description.MediaTypeVideo, Formats: []format.Format{tc.video}},
			}}
			if got := descriptionVideoMetadata(desc); got != tc.want {
				t.Fatalf("metadata = %+v, want %+v", got, tc.want)
			}
		})
	}
	video := &description.Media{Type: description.MediaTypeVideo, Formats: []format.Format{&format.H264{SPS: metadataH264SPS}}}
	for _, desc := range []*description.Session{nil, {}, {Medias: []*description.Media{nil}}, {Medias: []*description.Media{video, video}},
		{Medias: []*description.Media{{Type: description.MediaTypeVideo, Formats: []format.Format{&format.H264{}, &format.H265{}}}}}} {
		if got := descriptionVideoMetadata(desc); got != (VideoMetadata{}) {
			t.Fatalf("ambiguous or absent video produced metadata: %+v", got)
		}
	}
}

func TestReducedVideoRatePreservesFractionWithoutOverflow(t *testing.T) {
	for _, tc := range []struct {
		n, d         uint64
		wantN, wantD uint32
	}{
		{60000, 2002, 30000, 1001}, {0, 1, 0, 0}, {1, 0, 0, 0},
		{math.MaxUint32, 2 * uint64(math.MaxUint32), 1, 2},
		{1, uint64(math.MaxUint32) + 1, 0, 0},
	} {
		if n, d := reducedRate(tc.n, tc.d); n != tc.wantN || d != tc.wantD {
			t.Fatalf("rate %d/%d became %d/%d, want %d/%d", tc.n, tc.d, n, d, tc.wantN, tc.wantD)
		}
	}
}

func TestVideoMetadataFollowsUpstreamGeneration(t *testing.T) {
	f := newFixture(t)
	main := f.streams["/main"]
	codec := main.Desc.Medias[0].Formats[0].(*format.H264)
	_, pps := codec.SafeParams()
	codec.SafeSetParams(metadataH264SPS, pps)
	main.ReloadDesc()
	s := startProxy(t, f.config())
	await(t, func() bool { return len(s.VideoMetadata()) == 2 })
	first := s.VideoMetadata()
	if got := first["stream1"]; got.Width != 352 || got.Height != 288 || got.FrameRateNumerator != 15 {
		t.Fatalf("first connection metadata incorrect: %+v", got)
	}
	first["stream1"] = VideoMetadata{Codec: "changed by caller"}
	if s.VideoMetadata()["stream1"].Codec != "H264" {
		t.Fatal("caller changed the server metadata")
	}

	// Refuse reconnects long enough to inspect the disconnected generation.
	f.status.Store(int64(base.StatusServiceUnavailable))
	f.mu.Lock()
	connections := make([]*gortsplib.ServerConn, 0, len(f.conns))
	for conn := range f.conns {
		connections = append(connections, conn)
	}
	f.mu.Unlock()
	for _, conn := range connections {
		conn.Close()
	}
	await(t, func() bool { return len(s.VideoMetadata()) == 0 })
	// The next SDP deliberately lacks timing/resolution. Old facts must vanish.
	codec.SafeSetParams(nil, pps)
	main.ReloadDesc()
	f.status.Store(0)
	await(t, func() bool { return len(s.VideoMetadata()) == 2 })
	if got := s.VideoMetadata()["stream1"]; got != (VideoMetadata{Codec: "H264"}) {
		t.Fatalf("reconnect retained stale metadata: %+v", got)
	}
	s.Close()
	if len(s.VideoMetadata()) != 0 {
		t.Fatal("closed proxy still advertises live metadata")
	}
}
