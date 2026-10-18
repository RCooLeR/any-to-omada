package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/RCooLeR/any-to-omada/internal/config"
)

func metadataRow(t *testing.T, method, configName, response string) map[string]any {
	t.Helper()
	var fields map[string]any
	decoder := json.NewDecoder(strings.NewReader(response))
	decoder.UseNumber()
	if err := decoder.Decode(&fields); err != nil {
		t.Fatal(err)
	}
	return map[string]any{"method": method, "configuration_name": configName, "response": fields}
}

func TestSourceMetadataUsesNativeLensIndexesAndKnownFields(t *testing.T) {
	_, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	s := newSource(config.Source{ID: "dual"}, "", nil, &memorySink{}, cancel)
	rows := []struct {
		kind, method, configName, response string
	}{
		{"identity", "magicBox.getDeviceType", "", `{"result":true,"params":{"type":"IPC-fixture","serialNumber":"private-serial"}}`},
		{"identity", "magicBox.getSoftwareVersion", "", `{"result":true,"params":{"version":{"Version":"2.680.fixture.R","BuildDate":"2024-12-02","other":"private-version-field"}}}`},
		{"configuration", "configManager.getConfig", "Encode", `{"result":true,"params":{"table":[{"MainFormat":[{"Video":{"Compression":"H.265","Width":1920,"Height":1080,"FPS":25,"BitRate":1024,"BitRateControl":"CBR","WaterMarkData":"private-watermark"}},{"Video":{"Width":9999}}],"ExtraFormat":[{"Video":{"Compression":"H.264","Width":640,"Height":480,"FPS":25,"BitRate":512,"BitRateControl":"CBR"}}]},null,{"MainFormat":[{"Video":{"Compression":"H.264","Width":2560,"Height":1440,"FPS":12.5,"BitRate":2048,"BitRateControl":"VBR"}}]}]}}`},
	}
	for _, row := range rows {
		if err := s.Write("dual", "dvrip", row.kind, metadataRow(t, row.method, row.configName, row.response)); err != nil {
			t.Fatal(err)
		}
	}
	got := s.metadata()
	if got.Model != "IPC-fixture" || got.Firmware != "2.680.fixture.R" || got.BuildDate != "2024-12-02" || len(got.Encoders) != 2 {
		t.Fatal("identity or native encoder indexes were lost")
	}
	if got.Encoders[0].Main != (SourceEncoder{Codec: "H265", Width: 1920, Height: 1080, FPS: 25, BitrateKbps: 1024, BitrateMode: "CBR"}) ||
		got.Encoders[0].Sub != (SourceEncoder{Codec: "H264", Width: 640, Height: 480, FPS: 25, BitrateKbps: 512, BitrateMode: "CBR"}) || got.Encoders[2].Main.FPS != 12.5 {
		t.Fatal("encoder format, native codec or numeric values changed")
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "private") {
		t.Fatal("unknown identity or encoder fields entered metadata")
	}
	delete(got.Encoders, 0)
	if len(s.metadata().Encoders) != 2 {
		t.Fatal("metadata caller changed the shared encoder snapshot")
	}
}

func TestSourceMetadataIgnoresUnsupportedAndUnrelatedConfiguration(t *testing.T) {
	s := &source{}
	s.recordMetadata(metadataRow(t, "magicBox.getDeviceType", "", `{"result":true,"params":{"type":"IPC-fixture"}}`))
	for _, row := range []map[string]any{
		metadataRow(t, "magicBox.getDeviceType", "", `{"result":false,"params":{"type":"wrong"}}`),
		metadataRow(t, "magicBox.getSoftwareVersion", "", `{"result":false,"params":{"version":{"Version":"wrong"}}}`),
		metadataRow(t, "configManager.getConfig", "SmartMotionDetect", `{"result":true,"params":{"table":[{"MainFormat":[{"Video":{"Width":1920}}]}]}}`),
		metadataRow(t, "configManager.getConfig", "Encode", `{"result":true,"params":{"table":{"unexpected":true}}}`),
	} {
		s.recordMetadata(row)
	}
	got := s.metadata()
	if got.Model != "IPC-fixture" || got.Firmware != "" || len(got.Encoders) != 0 {
		t.Fatal("rejected or unrelated read supplied metadata")
	}
}

func TestSourceEncoderDoesNotInventMissingOrInvalidProperties(t *testing.T) {
	row := metadataRow(t, "configManager.getConfig", "Encode", `{"result":true,"params":{"table":[{"MainFormat":[{"Video":{"Compression":"unknown","Width":-1,"Height":1.5,"FPS":0,"BitRate":"1024","BitRateControl":"unknown"}}],"ExtraFormat":[{"Video":{"Compression":"H.264","Width":640,"Height":480}}]}]}}`)
	s := &source{}
	s.recordMetadata(row)
	got := s.metadata().Encoders[0]
	if got.Main != (SourceEncoder{}) || got.Sub != (SourceEncoder{Codec: "H264", Width: 640, Height: 480}) {
		t.Fatal("invalid or absent numeric settings became advertised values")
	}
	for _, value := range []any{nil, json.Number("NaN"), json.Number("Inf"), json.Number("1e999"), true, "25"} {
		if metadataNumber(value) != 0 {
			t.Fatal("invalid metadata number accepted")
		}
	}
}

func TestSourceMetadataStartsEmptyForEveryCaptureGeneration(t *testing.T) {
	s := &source{metadataValue: SourceMetadata{Model: "old-model", Firmware: "old-version", BuildDate: "old-date",
		Encoders: map[int]SourceEncoders{0: {Main: SourceEncoder{Codec: "H265", Width: 1920, Height: 1080}}}}}
	s.startGeneration()
	if got := s.metadata(); got.Model != "" || got.Firmware != "" || got.BuildDate != "" || len(got.Encoders) != 0 || s.snapshot().State != "connecting" {
		t.Fatal("new capture retained metadata from the previous generation")
	}
	s.recordMetadata(metadataRow(t, "magicBox.getDeviceType", "", `{"result":true,"params":{"type":"new-model"}}`))
	s.recordMetadata(metadataRow(t, "magicBox.getSoftwareVersion", "", `{"result":false,"params":{"version":{"Version":"old-version"}}}`))
	s.recordMetadata(metadataRow(t, "configManager.getConfig", "Encode", `{"result":true,"params":{"table":{"unexpected":true}}}`))
	if got := s.metadata(); got.Model != "new-model" || got.Firmware != "" || got.BuildDate != "" || len(got.Encoders) != 0 {
		t.Fatal("new identity mixed with previous firmware or encoder metadata")
	}
}
