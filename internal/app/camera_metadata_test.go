package app

import (
	"testing"

	"github.com/RCooLeR/any-to-omada/internal/camerartsp"
)

func TestVideoMetadataRejectsConflictingEncoderConfiguration(t *testing.T) {
	observed := camerartsp.VideoMetadata{Codec: "H265", Width: 1920, Height: 1080, FrameRateNumerator: 25, FrameRateDenominator: 1}
	configured := SourceEncoder{Codec: "H264", Width: 640, Height: 480, FPS: 15, BitrateKbps: 512, BitrateMode: "CBR"}
	got := reconcileVideoMetadata(observed, configured)
	if got.Codec != "H265" || got.Width != 1920 || got.Height != 1080 || got.FrameRateNumerator != 25 || got.FrameRateDenominator != 1 {
		t.Fatalf("live stream metadata changed: %+v", got)
	}
	if got.BitrateKbps != 0 || got.BitrateMode != "" {
		t.Fatalf("conflicting configuration leaked: %+v", got)
	}
}

func TestVideoMetadataFillsOnlyMissingMatchingStreamFields(t *testing.T) {
	configured := SourceEncoder{Codec: "H264", Width: 640, Height: 480, FPS: 25, BitrateKbps: 512, BitrateMode: "CBR"}
	got := reconcileVideoMetadata(camerartsp.VideoMetadata{Codec: "H264"}, configured)
	if got.Width != 640 || got.Height != 480 || got.FrameRateNumerator != 25000 || got.FrameRateDenominator != 1000 || got.BitrateKbps != 512 || got.BitrateMode != "cbr" {
		t.Fatalf("matching configuration not applied: %+v", got)
	}
	got = reconcileVideoMetadata(camerartsp.VideoMetadata{Codec: "H264", Width: 1280, Height: 720, FrameRateNumerator: 30000, FrameRateDenominator: 1001}, configured)
	if got.Width != 1280 || got.Height != 720 || got.FrameRateNumerator != 30000 || got.FrameRateDenominator != 1001 {
		t.Fatalf("configuration overwrote stream headers: %+v", got)
	}
	got = reconcileVideoMetadata(camerartsp.VideoMetadata{}, configured)
	if got.Codec != "" || got.Width != 0 || got.BitrateKbps != 0 {
		t.Fatalf("configuration fabricated an unknown stream: %+v", got)
	}
}
