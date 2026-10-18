package omadalink

import (
	"bufio"
	"bytes"
	"testing"
)

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte(syntheticFrame), false)
	f.Add([]byte(syntheticFrame+"\r\n"), true)
	f.Add([]byte("--start-boundary--\r\nContent-Length: 99999999999999999999\r\n"), false)
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x00}, false)
	f.Fuzz(func(t *testing.T, data []byte, trailing bool) {
		if len(data) > 2*MaxFrameSize {
			t.Skip()
		}
		frame, err := ReadFrame(bufio.NewReaderSize(bytes.NewReader(data), 16), trailing)
		if err != nil {
			return
		}
		encoded, err := Encode(frame, trailing)
		if err != nil || len(encoded) > MaxFrameSize {
			t.Fatalf("accepted frame could not be boundedly encoded: %v", err)
		}
		again, err := ReadFrame(bufio.NewReader(bytes.NewReader(encoded)), trailing)
		if err != nil || again.ContentType != frame.ContentType || !bytes.Equal(again.Body, frame.Body) {
			t.Fatalf("accepted frame could not be round-tripped: %v", err)
		}
	})
}
