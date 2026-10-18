package omadalink

import (
	"encoding/json"
	"testing"
)

func TestEncodeResponseStringsUsesNativeAlphabetAndKeepsNumbers(t *testing.T) {
	raw := json.RawMessage(`{"error_code":0,"device_info":{"basic_info":{"device_model":"Omada 8MP Turret","mac":"28-91-04-2b-b3-4a","features":3,"languages":["Spanish Latin America","English"]}},"video":{"main":{"resolution":"3840*2160","frame_rate":"65561"}}}`)
	encoded, err := EncodeResponseStrings(raw)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	basic := value["device_info"].(map[string]any)["basic_info"].(map[string]any)
	if basic["device_model"] != "Omada%208MP%20Turret" || basic["mac"] != "28-91-04-2b-b3-4a" || basic["features"] != float64(3) ||
		basic["languages"].([]any)[0] != "Spanish%20Latin%20America" || value["error_code"] != float64(0) {
		t.Fatal("string values were not percent-encoded with the encodeURIComponent alphabet")
	}
	main := value["video"].(map[string]any)["main"].(map[string]any)
	if main["resolution"] != "3840*2160" || main["frame_rate"] != "65561" {
		t.Fatal("asterisk or digits were altered")
	}
	for _, invalid := range []string{`[1,2]`, `"text"`, `{"a":1} {"b":2}`} {
		if _, err := EncodeResponseStrings(json.RawMessage(invalid)); err == nil {
			t.Fatal("non-object or trailing JSON was accepted")
		}
	}
}
