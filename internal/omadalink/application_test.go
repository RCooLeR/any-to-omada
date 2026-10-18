package omadalink

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

func TestApplicationFramesFragmentedAndCoalesced(t *testing.T) {
	heartbeat, err := EncodeHeartbeat(32768)
	if err != nil {
		t.Fatal(err)
	}
	response := "--start-boundary--\r\nContent-Length:64\r\nContent-Type: Response\r\n" + `{"id":32768,"method":"response","responseData":{"error_code":0}}` + endBoundary
	for _, separator := range []string{"", "\r\n"} {
		t.Run(strconv.Quote(separator), func(t *testing.T) {
			wire := append(append(append([]byte{}, heartbeat...), separator...), response...)
			source := &singleByteReader{data: wire}
			r := bufio.NewReader(source)
			first, err := ReadApplicationFrame(r)
			if err != nil || first.ContentType != ApplicationRequest {
				t.Fatalf("fragmented heartbeat failed: %v", err)
			}
			second, err := ReadApplicationFrame(r)
			if err != nil || second.ContentType != ApplicationResponse || string(second.Body) != `{"id":32768,"method":"response","responseData":{"error_code":0}}` {
				t.Fatalf("coalesced response failed: %v", err)
			}
			if source.readPastEnd || len(source.data) != 0 {
				t.Fatal("decoder read beyond the selected end boundary")
			}
		})
	}
}

func TestApplicationOpaqueObjectsAndBound(t *testing.T) {
	body := `{"method":"unimplemented","marker":"--end-boundary--","other":[1,true]}`
	wire := startBoundary + "Content-Type:Request\r\nContent-Length:" + strconv.Itoa(len(body)) + "\r\n" + body + endBoundary
	frame, err := ReadApplicationFrame(bufio.NewReader(strings.NewReader(wire)))
	if err != nil || string(frame.Body) != body {
		t.Fatalf("length-delimited opaque JSON changed: %v", err)
	}

	overhead := len(startBoundary) + len("Content-Type:Response\r\nContent-Length:32768\r\n") + len(endBoundary)
	body = `{"x":"` + strings.Repeat("x", MaxApplicationFrameSize-overhead-len(`{"x":""}`)) + `"}`
	wire = startBoundary + "Content-Type:Response\r\nContent-Length:" + strconv.Itoa(len(body)) + "\r\n" + body + endBoundary
	if len(wire) != MaxApplicationFrameSize {
		t.Fatal("invalid test boundary")
	}
	if _, err := ReadApplicationFrame(bufio.NewReader(strings.NewReader(wire))); err != nil {
		t.Fatalf("exact application bound failed: %v", err)
	}
	tooLargeHeader := startBoundary + "Content-Type:Response\r\nContent-Length:" + strconv.Itoa(len(body)+1) + "\r\n"
	if _, err := ReadApplicationFrame(bufio.NewReader(strings.NewReader(tooLargeHeader))); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized frame was not rejected before reading body: %v", err)
	}
}

func TestApplicationMalformedFramesAndTruncation(t *testing.T) {
	wire, err := EncodeHeartbeat(32768)
	if err != nil {
		t.Fatal(err)
	}
	for length := range len(wire) {
		_, err := ReadApplicationFrame(bufio.NewReader(bytes.NewReader(wire[:length])))
		want := io.ErrUnexpectedEOF
		if length == 0 {
			want = io.EOF
		}
		if !errors.Is(err, want) {
			t.Fatalf("truncated prefix%d: expected %v, got %v", length, want, err)
		}
	}
	for _, malformed := range []string{
		"\r\n\r\n" + string(wire),
		strings.Replace(string(wire), "Request", "Spake2", 1),
		strings.Replace(string(wire), "Request", "synthetic-private-type", 1),
		strings.Replace(string(wire), "Length:33", "Length:-1", 1),
		strings.Replace(string(wire), "Length:33", "Other:33", 1),
		strings.Replace(string(wire), "Content-Length:33", "Content-Type:Request", 1),
		strings.Replace(string(wire), "Content-Type:Request", "Content-Length:33", 1),
		strings.Replace(string(wire), "Length:33\r\n", "Length:33\r\n\r\n", 1),
		startBoundary + "Content-Type:Request\r\nContent-Length:2\r\n[]" + endBoundary,
	} {
		if _, err := ReadApplicationFrame(bufio.NewReader(strings.NewReader(malformed))); !errors.Is(err, ErrInvalidFrame) || strings.Contains(err.Error(), "synthetic-private") {
			t.Fatalf("malformed frame accepted or reflected in error: %v", err)
		}
	}
	if _, err := ReadApplicationFrame(nil); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("nil application reader accepted: %v", err)
	}
}

func FuzzReadApplicationFrame(f *testing.F) {
	heartbeat, err := EncodeHeartbeat(FirstMessageID)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(heartbeat)
	f.Add(append([]byte("\r\n"), heartbeat...))
	f.Add([]byte("not a frame"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		frame, err := ReadApplicationFrame(bufio.NewReader(bytes.NewReader(wire)))
		if err != nil {
			return
		}
		if len(frame.Body) > MaxApplicationFrameSize || !json.Valid(frame.Body) || !applicationType(frame.ContentType) {
			t.Fatal("successful decode violated application frame bounds")
		}
	})
}
