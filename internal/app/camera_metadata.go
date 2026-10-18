package app

import (
	"math"
	"strings"

	"github.com/RCooLeR/any-to-omada/internal/camerartsp"
	"github.com/RCooLeR/any-to-omada/internal/omadafront"
)

// cameraMetadata combines physical identity with the selected lens's current RTSP facts and
// compatible encoder configuration.
func cameraMetadata(camera *camera, source *source) omadafront.Metadata {
	facts := source.metadata()
	brand := brandNames[source.cfg.Brand]
	if brand == "" {
		// Generic ONVIF sources are named by the manufacturer they report.
		brand = facts.Manufacturer
	}
	result := omadafront.Metadata{Name: camera.cfg.ID, Brand: brand, Model: facts.Model, Firmware: facts.Firmware,
		BuildDate: facts.BuildDate, SoftwareVersion: Version, Video: map[string]omadafront.VideoMetadata{}}
	if camera.media == nil {
		return result
	}
	encoders := facts.Encoders[camera.cfg.SourceIndex]
	for profile, observed := range camera.media.VideoMetadata() {
		name, configured := "main", encoders.Main
		if profile == "stream2" {
			name, configured = "minor", encoders.Sub
		}
		result.Video[name] = reconcileVideoMetadata(observed, configured)
	}
	return result
}

// brandNames are the display names of configured source brands.
var brandNames = map[string]string{"imou": "Imou", "dahua": "Dahua", "amcrest": "Amcrest", "hikvision": "Hikvision", "annke": "Annke",
	"reolink": "Reolink", "axis": "Axis", "hanwha": "Hanwha", "uniview": "Uniview", "tapo": "Tapo", "bosch": "Bosch", "vivotek": "Vivotek", "foscam": "Foscam"}

// reconcileVideoMetadata gives active SDP facts priority and fills configuration fields only
// when both sources report the same nonempty codec.
func reconcileVideoMetadata(observed camerartsp.VideoMetadata, configured SourceEncoder) omadafront.VideoMetadata {
	value := omadafront.VideoMetadata{Codec: observed.Codec, Width: observed.Width, Height: observed.Height,
		FrameRateNumerator: observed.FrameRateNumerator, FrameRateDenominator: observed.FrameRateDenominator}
	// The current SDP takes precedence. Configuration may fill absent fields
	// only for the same codec, avoiding mixed metadata after an encoder change.
	if observed.Codec != "" && observed.Codec == configured.Codec {
		value.BitrateKbps, value.BitrateMode = configured.BitrateKbps, strings.ToLower(configured.BitrateMode)
		if value.Width == 0 || value.Height == 0 {
			value.Width, value.Height = configured.Width, configured.Height
		}
		if value.FrameRateNumerator == 0 && configured.FPS > 0 && configured.FPS <= 240 {
			value.FrameRateNumerator = uint32(math.Round(configured.FPS * 1000))
			value.FrameRateDenominator = 1000
		}
	}
	return value
}
