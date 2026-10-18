package camerartsp

import (
	"math"

	"github.com/bluenviron/gortsplib/v5/pkg/description"
	"github.com/bluenviron/gortsplib/v5/pkg/format"
	"github.com/bluenviron/mediacommon/v2/pkg/codecs/h264"
	"github.com/bluenviron/mediacommon/v2/pkg/codecs/h265"
)

// VideoMetadata describes the video advertised by the current upstream SDP.
// Dimensions are pixels. The reduced frame-rate fraction is nominal SPS timing,
// not a measured rate or an encoder-setting guarantee. Zero dimensions or either
// zero fraction component mean unavailable; they must not become camera defaults.
type VideoMetadata struct {
	Codec                string `json:"codec"`
	Width                int    `json:"width,omitempty"`
	Height               int    `json:"height,omitempty"`
	FrameRateNumerator   uint32 `json:"frame_rate_numerator,omitempty"`
	FrameRateDenominator uint32 `json:"frame_rate_denominator,omitempty"`
}

// VideoMetadata returns detached snapshots keyed by stream1/stream2, only for
// ready upstreams with one supported video format. Each reconnect replaces the
// SDP-derived metadata; a disconnected, stopped or rejected stream is omitted.
// This method performs no network I/O and is safe for concurrent callers.
func (s *Server) VideoMetadata() map[string]VideoMetadata {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]VideoMetadata)
	if s.closed || s.authFailed {
		return result
	}
	for _, p := range s.profiles {
		if p.stream != nil && p.status.State == "ready" && p.video.Codec != "" {
			result[p.name] = p.video
		}
	}
	return result
}

// descriptionVideoMetadata reads codec, dimensions and nominal SPS timing from
// one unambiguous H.264/H.265 video format; absent or invalid values stay zero.
func descriptionVideoMetadata(desc *description.Session) VideoMetadata {
	if desc == nil {
		return VideoMetadata{}
	}
	var video format.Format
	for _, media := range desc.Medias {
		if media == nil || media.Type != description.MediaTypeVideo {
			continue
		}
		// One Omada profile describes one encoded video stream. Do not choose an
		// arbitrary format when the upstream advertises several video sources.
		if video != nil || len(media.Formats) != 1 {
			return VideoMetadata{}
		}
		video = media.Formats[0]
	}
	var result VideoMetadata
	switch codec := video.(type) {
	case *format.H264:
		result.Codec = "H264"
		data, _ := codec.SafeParams()
		var sps h264.SPS
		if len(data) == 0 || len(data) > 4096 || sps.Unmarshal(data) != nil {
			return result
		}
		result.Width, result.Height = sps.Width(), sps.Height()
		if sps.VUI != nil && sps.VUI.TimingInfo != nil {
			timing := sps.VUI.TimingInfo
			result.FrameRateNumerator, result.FrameRateDenominator = reducedRate(uint64(timing.TimeScale), 2*uint64(timing.NumUnitsInTick))
		}
	case *format.H265:
		result.Codec = "H265"
		_, data, _ := codec.SafeParams()
		var sps h265.SPS
		if len(data) == 0 || len(data) > 4096 || sps.Unmarshal(data) != nil {
			return result
		}
		result.Width, result.Height = sps.Width(), sps.Height()
		if sps.VUI != nil && sps.VUI.TimingInfo != nil {
			timing := sps.VUI.TimingInfo
			ticks := uint64(timing.NumUnitsInTick)
			if timing.POCProportionalToTimingFlag {
				ticks *= uint64(timing.NumTicksPOCDiffOneMinus1) + 1
			}
			result.FrameRateNumerator, result.FrameRateDenominator = reducedRate(uint64(timing.TimeScale), ticks)
		}
	}
	// Reject impossible crop/size results, including underflow in malformed SPS.
	if result.Width < 1 || result.Height < 1 || result.Width > 65535 || result.Height > 65535 {
		result.Width, result.Height = 0, 0
	}
	return result
}

// reducedRate reduces a rational frame rate to 32-bit components, returning
// zeroes for missing timing or values that still overflow after reduction.
func reducedRate(numerator, denominator uint64) (uint32, uint32) {
	if numerator == 0 || denominator == 0 {
		return 0, 0
	}
	a, b := numerator, denominator
	for b != 0 {
		a, b = b, a%b
	}
	numerator, denominator = numerator/a, denominator/a
	if numerator > math.MaxUint32 || denominator > math.MaxUint32 {
		return 0, 0
	}
	return uint32(numerator), uint32(denominator)
}
