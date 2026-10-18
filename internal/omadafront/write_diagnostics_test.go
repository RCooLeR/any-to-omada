package omadafront

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestWriteDiagnosticsExposeOnlyKnownOperationNames(t *testing.T) {
	var request map[string]json.RawMessage
	if err := json.Unmarshal([]byte(`{"method":"set","system":{"basic":{"password":"private-value"},"dst_manual":{},"private-operation":"private-value"},"cloud_config":{"check_fw_version":"private-value"},"private-module":{"key":"private-value"},"video":null}`), &request); err != nil {
		t.Fatal(err)
	}
	want := []string{"cloud_config.check_fw_version", "system.basic", "system.dst_manual", "system.unknown", "unknown", "video:invalid"}
	if got := writeOperationLabels(request); !slices.Equal(got, want) {
		t.Fatalf("unexpected bounded diagnostic labels: %v", got)
	}
}
