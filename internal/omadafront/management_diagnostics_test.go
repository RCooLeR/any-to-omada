package omadafront

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestReadSelectorsPreserveNameTableAndStringArrayDistinctions(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		selectors  []string
		forms      []string
	}{
		{
			"captured scalar and array",
			`{"method":"get","msg_alarm":{"name":"chn1_msg_alarm_info"},"msg_alarm_plan":{"name":["arming_schedule_sound","arming_schedule_light"]}}`,
			[]string{"msg_alarm.name:chn1_msg_alarm_info", "msg_alarm_plan.name:arming_schedule_light", "msg_alarm_plan.name:arming_schedule_sound"},
			[]string{"name:array", "name:string"},
		},
		{
			"unsupported name and table",
			`{"method":"get","regionentrance_detection":{"version":"1","name":["detection","arming_schedule"],"table":["polygon_region_info","region_info"]},"pet_detection":{"table":"region_info"}}`,
			[]string{"pet_detection.table:region_info", "regionentrance_detection.name:arming_schedule", "regionentrance_detection.name:detection", "regionentrance_detection.table:polygon_region_info", "regionentrance_detection.table:region_info"},
			[]string{"name:array", "table:array", "table:string"},
		},
		{
			"firmware identity image and OSD vocabulary",
			`{"method":"get","device_info":{"name":"basic_info"},"image":{"name":["para","video_format"]},"OSD":{"name":"label_info"},"osd_capability":{"name":"capability"},"video":{"name":["main","minor"]},"video_capability":{"name":"main"}}`,
			[]string{"OSD.name:label_info", "device_info.name:basic_info", "image.name:para", "image.name:video_format", "osd_capability.name:capability", "video.name:main", "video.name:minor", "video_capability.name:main"},
			[]string{"name:array", "name:string"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			s := testServer(t, func(cfg *Config) { cfg.Logger = slog.New(slog.NewJSONHandler(&output, nil)) })
			path := login(t, s)
			output.Reset()
			status, response := request(t, s, path, tc.body)
			if status != http.StatusOK || len(response) != 1 || response["error_code"] != float64(unsupportedCode) {
				t.Fatal("selector diagnostics changed the unsupported response")
			}
			var fields struct {
				Selectors      []string `json:"read_selectors"`
				Forms          []string `json:"read_selector_forms"`
				UnknownModules int      `json:"unknown_read_modules"`
			}
			if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(fields.Selectors, tc.selectors) || !slices.Equal(fields.Forms, tc.forms) || fields.UnknownModules != 0 {
				t.Fatalf("unexpected selector labels: %+v", fields)
			}
		})
	}
}

func TestReadSelectorDiagnosticsNeverLogUnknownTextOrUnrelatedFields(t *testing.T) {
	var output bytes.Buffer
	s := testServer(t, func(cfg *Config) { cfg.Logger = slog.New(slog.NewJSONHandler(&output, nil)) })
	path := login(t, s)
	output.Reset()
	body := `{"method":"get","video":{"name":["main","private-selector-secret",null,{"private-selector-key":"private-selector-object"}],"table":"private-table-secret","password":"private-password","auth_code":"private-proof","nonce":"private-nonce","private-field":"private-value"},"private-module-secret":{"name":"main"},"private-second-module":null,"system":{"name":"private-session-value"}}`
	request(t, s, path, body)
	var fields struct {
		Modules        []string `json:"read_modules"`
		Selectors      []string `json:"read_selectors"`
		Forms          []string `json:"read_selector_forms"`
		UnknownModules int      `json:"unknown_read_modules"`
	}
	if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if fields.UnknownModules != 2 || !slices.Equal(fields.Modules, []string{"system", "unknown", "video"}) ||
		!slices.Equal(fields.Selectors, []string{"system.name:unknown", "unknown", "video.name:invalid", "video.name:main", "video.name:unknown", "video.table:unknown"}) {
		t.Fatal("unknown selectors lost their fixed labels or module count")
	}
	for _, secret := range []string{"private-", "password", "auth_code", "nonce", "stok", strings.TrimSuffix(strings.TrimPrefix(path, "/stok="), "/ds"), body} {
		if strings.Contains(output.String(), secret) {
			t.Fatal("selector diagnostics exposed private input")
		}
	}
}

func TestReadSelectorDiagnosticsMalformedShapesAreFixedLabels(t *testing.T) {
	var body map[string]json.RawMessage
	if err := json.Unmarshal([]byte(`{"method":"get","video":{"name":null,"table":[]},"image":null,"system":{"password":"private-password"},"OSD":{"name":17}}`), &body); err != nil {
		t.Fatal(err)
	}
	labels, forms, unknown := readSelectorLabels(body)
	if !slices.Equal(labels, []string{"OSD.name:invalid", "image:invalid", "system:no_selector", "video.name:invalid", "video.table:empty"}) ||
		!slices.Equal(forms, []string{"invalid", "table:array"}) || unknown != 0 {
		t.Fatal("malformed selector values escaped fixed shape classification")
	}
}

func TestReadSelectorDiagnosticsRemainSortedDeduplicatedAndBounded(t *testing.T) {
	body := map[string]any{"method": "get"}
	for _, module := range []string{"motion_detection", "intrusion_detection", "regionentrance_detection", "regionexiting_detection", "vehicle_detection", "people_detection", "pet_detection"} {
		body[module] = map[string]any{"name": []string{"detection", "arming_schedule", "feature", "notify_list", "feature"}, "table": "region_info"}
	}
	private := make([]string, 1000)
	for i := range private {
		private[i] = "private-selector-" + strconv.Itoa(i)
	}
	body["video"] = map[string]any{"name": private}
	body["private-module-secret"] = map[string]any{"name": "private-payload-secret"}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= maxBodyBytes {
		t.Fatal("fixture exceeds request body limit")
	}
	var request map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &request); err != nil {
		t.Fatal(err)
	}
	labels, forms, unknown := readSelectorLabels(request)
	if len(labels) != 16 || !slices.IsSorted(labels) || !slices.Contains(labels, "truncated") || !slices.Contains(labels, "unknown") || unknown != 1 {
		t.Fatal("large selector set lost its bound or omission markers")
	}
	for i := 1; i < len(labels); i++ {
		if labels[i-1] == labels[i] {
			t.Fatal("duplicate selectors consumed the diagnostic bound")
		}
	}
	if !slices.Equal(forms, []string{"name:array", "table:string"}) || strings.Contains(strings.Join(labels, ","), "private-") {
		t.Fatal("large selector set leaked unknown data or lost its shape labels")
	}
}

func FuzzReadDiagnosticsOnlyEmitFixedVocabulary(f *testing.F) {
	f.Add([]byte(`{"method":"get","video":{"name":["main","private-selector"],"table":null},"private-module":"private-value"}`))
	f.Add([]byte(`{"method":"get","image":{"name":{}},"OSD":null,"motion_detection":{"table":["region_info",{},null,17]}}`))
	f.Add([]byte(`{"method":"get","device_info":{"name":"basic_info","password":"private-password"}}`))
	f.Add([]byte(`{"method":"get"}`))
	allowedModules := map[string]bool{"unknown": true, "truncated": true}
	allowedSelectors := map[string]bool{"unknown": true, "truncated": true}
	selectors := readSelectorVocabulary()
	for module, label := range readModuleVocabulary() {
		allowedModules[label] = true
		allowedSelectors[module+":invalid"] = true
		allowedSelectors[module+":no_selector"] = true
		for _, field := range []string{"name", "table"} {
			prefix := module + "." + field + ":"
			for _, name := range append(slices.Clone(selectors[module]), "unknown", "invalid", "empty") {
				allowedSelectors[prefix+name] = true
			}
		}
	}
	allowedForms := map[string]bool{"name:string": true, "name:array": true, "table:string": true, "table:array": true, "invalid": true}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > maxBodyBytes {
			return
		}
		var request map[string]json.RawMessage
		if json.Unmarshal(input, &request) != nil || request == nil {
			return
		}
		modules := readModuleLabels(request)
		labels, forms, unknown := readSelectorLabels(request)
		if len(modules) > 8 || len(labels) > 16 || len(forms) > 5 || unknown < 0 || unknown > len(request) ||
			!slices.IsSorted(modules) || !slices.IsSorted(labels) || !slices.IsSorted(forms) {
			t.Fatal("diagnostic bounds or sorting violated")
		}
		for _, module := range modules {
			if !allowedModules[module] {
				t.Fatal("module output contained unrecognized input")
			}
		}
		for _, label := range labels {
			if !allowedSelectors[label] {
				t.Fatal("selector output contained unrecognized input")
			}
		}
		for _, form := range forms {
			if !allowedForms[form] {
				t.Fatal("selector form output contained unrecognized input")
			}
		}
	})
}
