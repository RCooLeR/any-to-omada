package omadafront

import (
	"encoding/json"
)

// writeOperationLabels records only observed operation names, never their values.
// Unknown input is represented by a fixed label, including arbitrary JSON keys.
func writeOperationLabels(request map[string]json.RawMessage) []string {
	known := map[string]map[string]bool{
		"system":       {"basic": true, "dst_manual": true, "set_time": true},
		"video":        {"force_iframe": true},
		"cloud_config": {"check_fw_version": true},
	}
	for module, sections := range readSelectorVocabulary() {
		if known[module] == nil {
			known[module] = make(map[string]bool)
		}
		for _, section := range sections {
			known[module][section] = true
		}
	}
	labels := make(map[string]bool)
	for module, raw := range request {
		if module == "method" {
			continue
		}
		vocabulary, ok := known[module]
		if !ok {
			labels["unknown"] = true
			continue
		}
		var operations map[string]json.RawMessage
		if json.Unmarshal(raw, &operations) != nil || len(operations) == 0 {
			labels[module+":invalid"] = true
			continue
		}
		for operation := range operations {
			if vocabulary[operation] {
				labels[module+"."+operation] = true
			} else {
				labels[module+".unknown"] = true
			}
		}
	}
	return boundedReadLabels(labels, 16)
}
