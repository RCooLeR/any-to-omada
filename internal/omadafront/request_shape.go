package omadafront

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
)

var shapeName = regexp.MustCompile(`^[A-Za-z0-9_]{1,48}$`)

// sensitiveName matches field names that may label secrets; they are shown as
// "redacted" so even the existence of such a field is not spelled out.
var sensitiveName = regexp.MustCompile(`(?i)pass|pwd|secret|token|auth|key|cred|cookie|session|nonce|stok|cert`)

// RequestShape names a request's modules, operations and field names without
// any value, for operations the translator does not implement yet. Selector
// strings of reads (name, table) are section names and are kept. A name
// outside a conservative identifier alphabet becomes "?". Payload values are
// omitted; read selectors are retained only as bounded identifier labels.
func RequestShape(raw json.RawMessage) []string {
	var request map[string]json.RawMessage
	if json.Unmarshal(raw, &request) != nil || request == nil {
		return []string{"invalid"}
	}
	return requestShape(request)
}

func requestShape(request map[string]json.RawMessage) []string {
	var method string
	_ = json.Unmarshal(request["method"], &method)
	var shapes []string
	for _, module := range sortedKeys(request, 8) {
		if module == "method" {
			continue
		}
		var operations map[string]json.RawMessage
		if json.Unmarshal(request[module], &operations) != nil || operations == nil {
			shapes = append(shapes, shapeLabel(module)+":"+jsonKind(request[module]))
			continue
		}
		for _, operation := range sortedKeys(operations, 8) {
			label := shapeLabel(module) + "." + shapeLabel(operation)
			value := operations[operation]
			if method == "get" && (operation == "name" || operation == "table") {
				label += "=" + strings.Join(selectorShape(value), ",")
			} else if fields := objectKeys(value); fields != nil {
				label += "{" + strings.Join(fields, ",") + "}"
			} else {
				label += ":" + jsonKind(value)
			}
			shapes = append(shapes, label)
		}
	}
	if len(shapes) > 16 {
		shapes = append(shapes[:15], "truncated")
	}
	return shapes
}

func selectorShape(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{shapeLabel(one)}
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil {
		return []string{jsonKind(raw)}
	}
	labels := make([]string, 0, min(len(many), 8))
	for _, name := range many[:min(len(many), 8)] {
		labels = append(labels, shapeLabel(name))
	}
	return labels
}

// objectKeys lists an object's field names, with one nested level for object
// fields, for example "speed" or "position{pan,tilt}".
func objectKeys(raw json.RawMessage) []string {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil
	}
	keys := sortedKeys(fields, 24)
	labels := make([]string, 0, len(keys))
	for _, key := range keys {
		label := shapeLabel(key)
		if label == "redacted" {
			labels = append(labels, label)
			continue
		}
		var nested map[string]json.RawMessage
		if json.Unmarshal(fields[key], &nested) == nil && nested != nil {
			label += "{" + strings.Join(func() []string {
				inner := sortedKeys(nested, 12)
				for i, name := range inner {
					inner[i] = shapeLabel(name)
				}
				return inner
			}(), ",") + "}"
		}
		labels = append(labels, label)
	}
	return labels
}

func sortedKeys(fields map[string]json.RawMessage, limit int) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if len(keys) > limit {
		keys = append(keys[:limit-1], "truncated")
	}
	return keys
}

func shapeLabel(name string) string {
	switch {
	case !shapeName.MatchString(name):
		return "?"
	case sensitiveName.MatchString(name):
		return "redacted"
	default:
		return name
	}
}

func jsonKind(raw json.RawMessage) string {
	text := strings.TrimSpace(string(raw))
	switch {
	case text == "":
		return "missing"
	case text[0] == '{':
		return "object"
	case text[0] == '[':
		return "array"
	case text[0] == '"':
		return "string"
	case text == "null":
		return "null"
	case text == "true" || text == "false":
		return "boolean"
	default:
		return "number"
	}
}
