package omadalink

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestAlgorithmOfferSelectsNativeVersion(t *testing.T) {
	for _, offer := range [][]byte{[]byte("1.0"), []byte("2.0"), bytes.Repeat([]byte{0xff}, 64)} {
		var incoming, outgoing bytes.Buffer
		if err := writeSyntheticServerFrame(&incoming, AlgorithmVersion, 1, offer); err != nil {
			t.Fatal(err)
		}
		progress := &handshakeProgress{}
		_, err := exchangeHandshake(context.Background(), bufio.NewReader(&incoming), &outgoing, "synthetic-registration", nil, progress)
		if !errors.Is(err, ErrHandshake) || !errors.Is(err, io.EOF) || progress.stage != stageReadParameters {
			t.Fatalf("valid offer did not advance to parameter read: %v", err)
		}
		frame, err := ReadFrame(bufio.NewReader(&outgoing), false)
		if err != nil {
			t.Fatal(err)
		}
		var reply handshakeMessage
		if json.Unmarshal(frame.Body, &reply) != nil || reply.Step == nil || *reply.Step != 2 || reply.Data != "MS4w" || reply.ErrorCode == nil || *reply.ErrorCode != 0 {
			t.Fatal("camera did not select version 1.0")
		}
		if progress.details.OfferedBytes != len(offer) || progress.details.PeerStepPresent || progress.details.PeerErrorCodePresent {
			t.Fatal("parameter read retained stale peer fields or lost offer length")
		}
		wantVersion := "other"
		if string(offer) == "1.0" {
			wantVersion = "1.0"
		}
		if progress.details.OfferVersion != wantVersion {
			t.Fatal("offer classification differs")
		}
	}
}

func TestAlgorithmOfferFailureDiagnostics(t *testing.T) {
	for _, test := range []struct {
		name, body, reason       string
		stepPresent, codePresent bool
		step, code               int
	}{
		{"empty", `{"step":1,"error_code":0,"data":""}`, "data_size", true, true, 1, 0},
		{"oversized", `{"step":1,"error_code":0,"data":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 65)) + `"}`, "data_size", true, true, 1, 0},
		{"base64", `{"step":1,"error_code":0,"data":"private-synthetic-payload"}`, "base64_data", true, true, 1, 0},
		{"remote", `{"step":1,"error_code":-17,"data":"private-synthetic-payload"}`, "remote_error", true, true, 1, -17},
		{"step", `{"step":7,"error_code":0,"data":"MS4w"}`, "unexpected_step", true, true, 7, 0},
		{"missing code", `{"step":1,"data":"MS4w"}`, "missing_error_code", true, false, 1, 0},
		{"wrong type", `{"step":1,"error_code":0,"data":42}`, "json_fields", false, false, 0, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := Encode(Frame{ContentType: AlgorithmVersion, Body: []byte(test.body)}, true)
			if err != nil {
				t.Fatal(err)
			}
			progress := &handshakeProgress{}
			_, err = readHandshakeMessageTracked(bufio.NewReader(bytes.NewReader(encoded)), AlgorithmVersion, 1, 1, 64, progress)
			d := progress.details
			if !errors.Is(err, ErrHandshake) || d.Reason != test.reason || d.PrefixCategory != "native" || d.PeerStepPresent != test.stepPresent || d.PeerErrorCodePresent != test.codePresent || d.PeerStep != test.step || d.PeerErrorCode != test.code {
				t.Fatalf("unexpected safe diagnostics: %+v; %v", d, err)
			}
			if strings.Contains(fmt.Sprint(d, err), "private-synthetic-payload") {
				t.Fatal("diagnostic contains peer data")
			}
		})
	}
}

func TestBoundedLeadingEmptyCRLFAndNoLookahead(t *testing.T) {
	for leading := 0; leading <= maxLeadingCRLF; leading++ {
		for _, trailing := range []bool{false, true} {
			body := []byte("\r\n{\"x\":1}")
			wire, err := Encode(Frame{ContentType: AlgorithmVersion, Body: body}, trailing)
			if err != nil {
				t.Fatal(err)
			}
			source := &singleByteReader{data: append([]byte(strings.Repeat("\r\n", leading)), wire...)}
			frame, err := ReadFrame(bufio.NewReader(source), trailing)
			if err != nil || !bytes.Equal(frame.Body, body) || source.readPastEnd || len(source.data) != 0 {
				t.Fatalf("leading lines or body whitespace changed framing: %v", err)
			}
		}
	}
	_, err := ReadFrame(bufio.NewReader(strings.NewReader(strings.Repeat("\r\n", maxLeadingCRLF+1)+syntheticFrame)), false)
	var failure *frameReadFailure
	if !errors.Is(err, ErrInvalidFrame) || !errors.As(err, &failure) || failure.reason != "frame_prefix_limit" {
		t.Fatal("excessive leading empty lines were accepted")
	}
}

func TestFrameDiagnosticPrefixCategories(t *testing.T) {
	for _, test := range []struct{ prefix, category string }{
		{"HTTP/1.1 400 Bad Request\r\n", "http"},
		{string([]byte{0x16, 3, 3, 0}) + strings.Repeat("x", 20), "tls"},
		{"private-synthetic-payload", "other"},
		{"--invalid-boundary--\r\n", "native"},
	} {
		_, err := ReadFrame(bufio.NewReader(strings.NewReader(test.prefix)), true)
		var failure *frameReadFailure
		if !errors.As(err, &failure) || failure.reason != "frame_boundary" || failure.prefix != test.category || strings.Contains(err.Error(), "private") {
			t.Fatalf("unsafe or incorrect prefix diagnostic: %v", err)
		}
	}
}

func TestVersionFrameWithSixLeadingBytes(t *testing.T) {
	// This synthetic public fixture has the reported total length, without
	// assuming that leading empty lines caused the unobserved NAS failure.
	body := []byte(`{"step": 1, "error_code": 0, "data": "MS4w"}` + "  ")
	wire, err := Encode(Frame{ContentType: AlgorithmVersion, Body: body}, true)
	if err != nil {
		t.Fatal(err)
	}
	wire = append([]byte("\r\n\r\n\r\n"), wire...)
	if len(wire) != 134 {
		t.Fatalf("unexpected fixture length %d", len(wire))
	}
	progress := &handshakeProgress{}
	data, err := readHandshakeMessageTracked(bufio.NewReader(bytes.NewReader(wire)), AlgorithmVersion, 1, 1, 64, progress)
	if err != nil || string(data) != "1.0" || progress.details.OfferVersion != "1.0" {
		t.Fatalf("bounded prefixed version frame rejected: %v", err)
	}
}
