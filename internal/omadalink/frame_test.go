package omadalink

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

const syntheticFrame = "--start-boundary--\r\nContent-Type: ALG_Ver\r\nContent-Length: 7\r\n{\"x\":1}\r\n--end-boundary--"

func TestObservedEnvelopeForms(t *testing.T) {
	for _, trailing := range []bool{false, true} {
		t.Run(strconv.FormatBool(trailing), func(t *testing.T) {
			wire := "--start-boundary--\r\nContent-Type:ALG_Ver\r\nContent-Length:7\r\n{\"x\":1}\r\n--end-boundary--"
			if trailing {
				wire = "--start-boundary--\r\nContent-Type:ALG_Ver\r\nContent-Length: 7\r\n{\"x\":1}\r\n--end-boundary--\r\n"
			}
			frame, err := ReadFrame(bufio.NewReader(strings.NewReader(wire)), trailing)
			if err != nil {
				t.Fatal(err)
			}
			if frame.ContentType != AlgorithmVersion || string(frame.Body) != `{"x":1}` {
				t.Fatal("decoded frame differs from synthetic wire fixture")
			}
			encoded, err := Encode(frame, trailing)
			if err != nil || string(encoded) != wire {
				t.Fatalf("encoded envelope differs from fixture: %v", err)
			}
		})
	}
}

func TestHeaderWhitespaceRemainsAccepted(t *testing.T) {
	for _, trailing := range []bool{false, true} {
		wire := syntheticFrame
		if trailing {
			wire += "\r\n"
		}
		frame, err := ReadFrame(bufio.NewReader(strings.NewReader(wire)), trailing)
		if err != nil || frame.ContentType != AlgorithmVersion || string(frame.Body) != `{"x":1}` {
			t.Fatalf("spaced header form was not accepted: %v", err)
		}
	}
}

func TestOpaqueJSONAndFollowingTLSBytesPreserved(t *testing.T) {
	// Unknown fields, UTF-8, whitespace and boundary text belong to the opaque body.
	body := []byte(" { \"data\": \"synthetic-\u0436--end-boundary--\", \"unknown\": [1, true] } \n")
	tlsBytes := []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}
	for _, trailing := range []bool{false, true} {
		encoded, err := Encode(Frame{ContentType: Spake2, Body: body}, trailing)
		if err != nil {
			t.Fatal(err)
		}
		for _, bufferSize := range []int{16, 4096} {
			r := bufio.NewReaderSize(bytes.NewReader(append(encoded, tlsBytes...)), bufferSize)
			if _, err := r.Peek(1); err != nil {
				t.Fatal(err)
			}
			frame, err := ReadFrame(r, trailing)
			if err != nil || frame.ContentType != Spake2 || !bytes.Equal(frame.Body, body) {
				t.Fatalf("opaque payload was not preserved: %v", err)
			}
			remainder, err := io.ReadAll(r)
			if err != nil || !bytes.Equal(remainder, tlsBytes) {
				t.Fatalf("following TLS bytes were lost: %v", err)
			}
		}
	}
}

func TestFragmentedFramesAndNoLookahead(t *testing.T) {
	for _, trailing := range []bool{false, true} {
		wire := syntheticFrame
		if trailing {
			wire += "\r\n"
		}
		source := &singleByteReader{data: []byte(wire)}
		if _, err := ReadFrame(bufio.NewReader(source), trailing); err != nil {
			t.Fatal(err)
		}
		if len(source.data) != 0 || source.readPastEnd {
			t.Fatal("decoder failed to stop at the selected frame ending")
		}
	}
}

func TestCoalescedFramesAndHeaderOrder(t *testing.T) {
	second := "--start-boundary--\r\nContent-Length:13\r\nContent-Type:Spake2\r\n{\"data\":\"\u0436\"}\r\n--end-boundary--"
	r := bufio.NewReader(strings.NewReader(syntheticFrame + "\r\n" + second))
	if _, err := ReadFrame(r, true); err != nil {
		t.Fatal(err)
	}
	frame, err := ReadFrame(r, false)
	if err != nil || frame.ContentType != Spake2 || string(frame.Body) != "{\"data\":\"\u0436\"}" {
		t.Fatalf("second coalesced frame was not decoded: %v", err)
	}
	if _, err := ReadFrame(r, false); !errors.Is(err, io.EOF) {
		t.Fatalf("expected clean end of stream, got %v", err)
	}
}

func TestFrameSizeBound(t *testing.T) {
	for _, trailing := range []bool{false, true} {
		// A five-digit body length keeps the header width constant at this boundary.
		overhead := len(startBoundary) + len("Content-Type:Spake2\r\nContent-Length:65536\r\n") + len(endBoundary)
		if trailing {
			overhead += 3 // NVR length separator and trailing CRLF.
		}
		body := []byte(`"` + strings.Repeat("x", MaxFrameSize-overhead-2) + `"`)
		encoded, err := Encode(Frame{ContentType: Spake2, Body: body}, trailing)
		if err != nil || len(encoded) != MaxFrameSize {
			t.Fatalf("exact frame limit was rejected: size=%d error=%v", len(encoded), err)
		}
		if _, err := ReadFrame(bufio.NewReader(bytes.NewReader(encoded)), trailing); err != nil {
			t.Fatal(err)
		}
		tooLarge := []byte(`"` + strings.Repeat("x", len(body)-1) + `"`)
		if _, err := Encode(Frame{ContentType: Spake2, Body: tooLarge}, trailing); !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("oversized encoded frame accepted: %v", err)
		}
		wire := startBoundary + "Content-Type: Spake2\r\nContent-Length: " + strconv.Itoa(len(tooLarge)) + "\r\n"
		if _, err := ReadFrame(bufio.NewReader(strings.NewReader(wire)), trailing); !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("oversized declared frame was not rejected before body read: %v", err)
		}
	}
}

func TestMalformedFrames(t *testing.T) {
	for _, test := range []struct {
		name string
		wire string
		err  error
	}{
		{"wrong start", strings.Replace(syntheticFrame, "start-boundary", "other-boundary", 1), ErrInvalidFrame},
		{"unsupported type", strings.Replace(syntheticFrame, "ALG_Ver", "unknown", 1), ErrInvalidFrame},
		{"negative length", strings.Replace(syntheticFrame, "Length: 7", "Length: -7", 1), ErrInvalidFrame},
		{"signed length", strings.Replace(syntheticFrame, "Length: 7", "Length: +7", 1), ErrInvalidFrame},
		{"nondecimal length", strings.Replace(syntheticFrame, "Length: 7", "Length: 7x", 1), ErrInvalidFrame},
		{"empty length", strings.Replace(syntheticFrame, "Length: 7", "Length:", 1), ErrInvalidFrame},
		{"zero length", strings.Replace(syntheticFrame, "Length: 7", "Length: 0", 1), ErrInvalidFrame},
		{"huge length", strings.Replace(syntheticFrame, "Length: 7", "Length: 99999999999999999999", 1), ErrFrameTooLarge},
		{"short length", strings.Replace(syntheticFrame, "Length: 7", "Length: 6", 1), ErrInvalidFrame},
		{"long length", strings.Replace(syntheticFrame+"!", "Length: 7", "Length: 8", 1), ErrInvalidFrame},
		{"duplicate type", strings.Replace(syntheticFrame, "Content-Length: 7", "Content-Type: Spake2", 1), ErrInvalidFrame},
		{"duplicate length", strings.Replace(syntheticFrame, "Content-Type: ALG_Ver", "Content-Length: 7", 1), ErrInvalidFrame},
		{"unknown header", strings.Replace(syntheticFrame, "Content-Length", "Other-Length", 1), ErrInvalidFrame},
		{"missing colon", strings.Replace(syntheticFrame, "Content-Length:", "Content-Length", 1), ErrInvalidFrame},
		{"bare newline", strings.Replace(syntheticFrame, "ALG_Ver\r\n", "ALG_Ver\n", 1), ErrInvalidFrame},
		{"oversized header", startBoundary + strings.Repeat("x", maxHeaderLineSize+1), ErrFrameTooLarge},
		{"blank separator", strings.Replace(syntheticFrame, "Length: 7\r\n", "Length: 7\r\n\r\n", 1), ErrInvalidFrame},
		{"invalid JSON", strings.Replace(syntheticFrame, `{"x":1}`, "invalid", 1), ErrInvalidFrame},
		{"wrong ending", strings.Replace(syntheticFrame, "end-boundary", "bad-boundary", 1), ErrInvalidFrame},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ReadFrame(bufio.NewReader(strings.NewReader(test.wire)), false); !errors.Is(err, test.err) {
				t.Fatalf("expected %v, got %v", test.err, err)
			}
		})
	}
}

func TestEveryTruncatedPrefixFails(t *testing.T) {
	wire := syntheticFrame + "\r\n"
	for length := range len(wire) {
		_, err := ReadFrame(bufio.NewReader(strings.NewReader(wire[:length])), true)
		want := io.ErrUnexpectedEOF
		if length == 0 {
			want = io.EOF
		}
		if !errors.Is(err, want) {
			t.Fatalf("prefix length%d: expected %v, got %v", length, want, err)
		}
	}
}

func TestInvalidEncodingAndNoPayloadInErrors(t *testing.T) {
	marker := "synthetic-private-value"
	for _, frame := range []Frame{
		{ContentType: ContentType(marker), Body: []byte(`{}`)},
		{ContentType: Spake2, Body: []byte(marker)},
		{ContentType: AlgorithmVersion},
	} {
		if _, err := Encode(frame, false); !errors.Is(err, ErrInvalidFrame) || strings.Contains(err.Error(), marker) {
			t.Fatalf("invalid encoding or error redaction failed: %v", err)
		}
	}
	wire := startBoundary + "Content-Type: Spake2\r\nContent-Length: " + strconv.Itoa(len(marker)) + "\r\n" + marker + endBoundary
	if _, err := ReadFrame(bufio.NewReader(strings.NewReader(wire)), false); !errors.Is(err, ErrInvalidFrame) || strings.Contains(err.Error(), marker) {
		t.Fatalf("decoder exposed invalid payload: %v", err)
	}
	if _, err := ReadFrame(nil, false); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("nil reader was not rejected: %v", err)
	}
}

type singleByteReader struct {
	data        []byte
	readPastEnd bool
}

func (r *singleByteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		r.readPastEnd = true
		return 0, errors.New("peer is waiting for reply")
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}
