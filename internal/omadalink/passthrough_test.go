package omadalink

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPassthroughRequestDecodesOnlyStringValues(t *testing.T) {
	raw := json.RawMessage(`{"method":"get","name%20key":"space%20plus+slash%2f","nested":{"list":["%d0%9a%d0%b0%d0%bc%d0%b5%d1%80%d0%b0",true,null,9007199254740993]},"literal":"%2520"}`)
	decoded, err := DecodePassthroughRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"literal":"%20","method":"get","name%20key":"space plus+slash/","nested":{"list":["Камера",true,null,9007199254740993]}}`
	if string(decoded) != want {
		t.Fatalf("object coding changed values or types: %s", decoded)
	}
	for _, invalid := range []string{`"%7b%7d"`, `[]`, `null`, `{"x":"%"}`, `{"x":"%gg"}`, `{"x":"%00"}`, `{"x":"%ff"}`, `{} {}`} {
		if _, err := DecodePassthroughRequest(json.RawMessage(invalid)); !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("invalid passthrough object was accepted: %v", err)
		}
	}
}

func TestPassthroughResponsePreservesNestedManagementFailure(t *testing.T) {
	response := json.RawMessage(`{"error_code":-40106,"result":{"name":"A +/% Камера","literal":"-_.!~*'()","items":["a:b",2,false,null]}}`)
	wire, err := EncodePassthroughResponse(7, response)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(wire, []byte(startBoundary+"Content-Type:Response\r\nContent-Length:")) || !bytes.HasSuffix(wire, []byte(endBoundary)) || bytes.HasSuffix(wire, []byte(endBoundary+"\r\n")) {
		t.Fatal("response framing differs from native serializer")
	}
	frame, err := ReadApplicationFrame(bufio.NewReader(bytes.NewReader(wire)))
	if err != nil || frame.ContentType != ApplicationResponse {
		t.Fatalf("invalid encoded response: %v", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(frame.Body, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope) != 3 || string(envelope["id"]) != "7" || string(envelope["error_code"]) != "0" || envelope["method"] != nil {
		t.Fatalf("incorrect correlated response envelope: %s", frame.Body)
	}
	if !bytes.Contains(envelope["responseData"], []byte(`"error_code":-40106`)) || !bytes.Contains(envelope["responseData"], []byte(`A%20%2b%2f%25%20%d0%9a%d0%b0%d0%bc%d0%b5%d1%80%d0%b0`)) || !bytes.Contains(envelope["responseData"], []byte(`-_.!~*'()`)) {
		t.Fatalf("incorrect native percent coding or nested result: %s", frame.Body)
	}
	decoded, err := DecodePassthroughRequest(envelope["responseData"])
	if err != nil {
		t.Fatal(err)
	}
	var original, roundTrip any
	if json.Unmarshal(response, &original) != nil || json.Unmarshal(decoded, &roundTrip) != nil {
		t.Fatal("round-trip object invalid")
	}
	a, _ := json.Marshal(original)
	b, _ := json.Marshal(roundTrip)
	if !bytes.Equal(a, b) {
		t.Fatal("response string coding was not reversible")
	}
}

func TestPassthroughResponseBoundsAndManagementContract(t *testing.T) {
	for _, invalid := range []string{`{}`, `{"error_code":null}`, `{"error_code":"0"}`, `[]`, `null`, `{"error_code":0} {}`} {
		if _, err := EncodePassthroughResponse(1, json.RawMessage(invalid)); !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("invalid management response accepted: %v", err)
		}
	}
	large := json.RawMessage(`{"error_code":0,"value":"` + strings.Repeat("a", MaxPassthroughFrameSize) + `"}`)
	if _, err := EncodePassthroughResponse(1, large); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized native response was not rejected: %v", err)
	}
	expanded := json.RawMessage(`{"error_code":0,"value":"` + strings.Repeat("/", 7000) + `"}`)
	if _, err := EncodePassthroughResponse(1, expanded); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("percent expansion bypassed native response limit: %v", err)
	}
}
