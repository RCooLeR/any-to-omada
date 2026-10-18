// Package isapievents reads a Hikvision (or OEM) camera's ISAPI alert stream
// and turns motion, smart line/intrusion/region and tamper alerts into
// brand-neutral events for the normalizer. It only reads: no camera setting is
// changed. Repeated "active" alerts are folded into one interval that ends on
// an "inactive" alert or after a quiet period.
package isapievents

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
	"github.com/RCooLeR/any-to-omada/internal/httpdigest"
)

const (
	protocol   = "isapi"
	streamPath = "/ISAPI/Event/notification/alertStream"
	infoPath   = "/ISAPI/System/deviceInfo"
	maxPart    = 64 << 10
)

type timings struct {
	request, idle, quiet, heartbeat time.Duration
}

// Hikvision sends a keep-alive about every 10 s; two minutes of silence is a stall.
var defaultTimings = timings{request: 10 * time.Second, idle: 2 * time.Minute, quiet: 5 * time.Second, heartbeat: time.Minute}

// ErrStream means the alert stream ended, stalled or was not multipart.
var ErrStream = errors.New("isapi alert stream unavailable")

// Run reads the alert stream until ctx ends or the stream fails; the caller
// reconnects. Rejected credentials return capture.ErrAuthentication.
func Run(ctx context.Context, device capture.Device, sink capture.Sink) error {
	return run(ctx, device, sink, defaultTimings)
}

type client struct {
	base   *url.URL
	http   *http.Client
	digest *httpdigest.Authorizer
	// challenge is the last Digest challenge, reused with increasing counts.
	mu        sync.Mutex
	challenge *httpdigest.Challenge
}

func newClient(device capture.Device, request time.Duration) *client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxConnsPerHost = 2
	transport.ResponseHeaderTimeout = request
	port := device.NativePort
	if port == 0 {
		port = 80
	}
	return &client{base: &url.URL{Scheme: "http", Host: net.JoinHostPort(device.Host, strconv.Itoa(port))},
		digest: &httpdigest.Authorizer{Username: device.Username, Password: device.Password},
		http:   &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// get performs one GET, answering a Digest challenge once. The caller closes
// the body of a 200 response.
func (c *client) get(ctx context.Context, path string) (*http.Response, error) {
	send := func(challenge *httpdigest.Challenge) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base.String()+path, nil)
		if err != nil {
			return nil, ErrStream
		}
		if challenge != nil {
			value, err := c.digest.Header(*challenge, http.MethodGet, path)
			if err != nil {
				return nil, capture.ErrAuthentication
			}
			req.Header.Set("Authorization", value)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, ErrStream
		}
		return resp, nil
	}
	c.mu.Lock()
	cached := c.challenge
	c.mu.Unlock()
	resp, err := send(cached)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		value := resp.Header.Get("WWW-Authenticate")
		drain(resp)
		parsed, err := httpdigest.Parse(value)
		if err != nil {
			return nil, capture.ErrAuthentication
		}
		if cached != nil && !parsed.Stale && parsed.Nonce == cached.Nonce {
			return nil, capture.ErrAuthentication
		}
		c.mu.Lock()
		c.challenge = &parsed
		c.mu.Unlock()
		if resp, err = send(&parsed); err != nil {
			return nil, err
		}
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		drain(resp)
		return nil, capture.ErrAuthentication
	default:
		drain(resp)
		return nil, ErrStream
	}
}

func drain(resp *http.Response) {
	// Error bodies are not needed. Reading them can stall indefinitely on the
	// long-lived stream request before its idle watchdog has started.
	_ = resp.Body.Close()
}

func run(ctx context.Context, device capture.Device, sink capture.Sink, t timings) error {
	c := newClient(device, t.request)
	defer c.http.CloseIdleConnections()
	if err := readIdentity(ctx, c, device.ID, sink, t.request); err != nil {
		return err
	}
	stream, cancel := context.WithCancel(ctx)
	defer cancel()
	resp, err := c.get(stream, streamPath)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") || params["boundary"] == "" {
		return ErrStream
	}
	if err := sink.Write(device.ID, protocol, "subscription", map[string]any{"stream": "alertStream"}); err != nil {
		return err
	}
	// A stalled stream sends no heartbeat; cancelling the request unblocks the reader.
	idle := time.AfterFunc(t.idle, cancel)
	defer idle.Stop()
	parts := make(chan alert, 8)
	failed := make(chan error, 1)
	go func() {
		failed <- readParts(resp.Body, params["boundary"], parts, stream.Done())
	}()
	tracker := newTracker(t.quiet)
	quiet := time.NewTicker(t.quiet / 4)
	defer quiet.Stop()
	var lastHeartbeat time.Time
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-failed:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err == nil || stream.Err() != nil {
				// The stream ended or the idle timer cancelled a stalled one.
				return ErrStream
			}
			return err
		case now := <-quiet.C:
			for _, ended := range tracker.expire(now) {
				if err := sink.Write(device.ID, protocol, "event", ended); err != nil {
					return err
				}
			}
		case alert := <-parts:
			idle.Reset(t.idle)
			if alert.heartbeat() {
				if time.Since(lastHeartbeat) >= t.heartbeat {
					lastHeartbeat = time.Now()
					if err := sink.Write(device.ID, protocol, "heartbeat", map[string]any{"event_type": "videoloss"}); err != nil {
						return err
					}
				}
				continue
			}
			if err := sink.Write(device.ID, protocol, "notification", alert.journal()); err != nil {
				return err
			}
			for _, event := range tracker.apply(alert, time.Now()) {
				if err := sink.Write(device.ID, protocol, "event", event); err != nil {
					return err
				}
			}
		}
	}
}

func readIdentity(ctx context.Context, c *client, deviceID string, sink capture.Sink, timeout time.Duration) error {
	call, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := c.get(call, infoPath)
	if err != nil {
		if errors.Is(err, capture.ErrAuthentication) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Model/firmware discovery is optional; a camera may grant event
		// access without implementing this metadata endpoint.
		return nil
	}
	defer resp.Body.Close()
	var info struct {
		Model                string `xml:"model"`
		FirmwareVersion      string `xml:"firmwareVersion"`
		FirmwareReleasedDate string `xml:"firmwareReleasedDate"`
	}
	if xml.NewDecoder(io.LimitReader(resp.Body, maxPart)).Decode(&info) != nil {
		// Identity is optional; the event stream does not depend on it.
		return nil
	}
	return sink.Write(deviceID, protocol, "identity", map[string]any{"manufacturer": "Hikvision", "model": clean(info.Model),
		"firmware": clean(info.FirmwareVersion), "build_date": clean(info.FirmwareReleasedDate)})
}

// alert is the part of an EventNotificationAlert the translator uses.
type alert struct {
	EventType       string   `xml:"eventType" json:"eventType"`
	EventState      string   `xml:"eventState" json:"eventState"`
	Description     string   `xml:"eventDescription" json:"-"`
	ChannelID       string   `xml:"channelID" json:"-"`
	DynChannelID    string   `xml:"dynChannelID" json:"-"`
	ActivePostCount string   `xml:"activePostCount" json:"-"`
	DateTime        string   `xml:"dateTime" json:"-"`
	TargetTypes     []string `xml:"-" json:"-"`
	RegionIDs       []string `xml:"-" json:"-"`
}

// heartbeat recognizes the keep-alive: an inactive video-loss alert, or on
// some firmware an alert described as "Heartbeat".
func (a alert) heartbeat() bool {
	return (strings.EqualFold(a.EventType, "videoloss") && strings.EqualFold(a.EventState, "inactive")) || strings.EqualFold(a.Description, "heartbeat")
}

func (a alert) journal() map[string]any {
	return map[string]any{"event_type": clean(a.EventType), "event_state": clean(a.EventState), "channel": clean(a.ChannelID),
		"dyn_channel": clean(a.DynChannelID), "active_post_count": clean(a.ActivePostCount), "date_time": clean(a.DateTime), "targets": a.TargetTypes, "regions": a.RegionIDs}
}

// readParts decodes XML or JSON alert parts and skips pictures and other parts.
// A part is delimited by its Content-Length when present, so an alert is
// delivered at once instead of when the next part's boundary arrives.
func readParts(body io.Reader, boundary string, parts chan<- alert, done <-chan struct{}) error {
	reader := bufio.NewReaderSize(body, 32<<10)
	delimiter := "--" + boundary
	if len(delimiter) > 72 || strings.ContainsAny(boundary, "\r\n") {
		return ErrStream
	}
	for {
		lineBytes, err := readLine(reader, maxPart)
		if err != nil {
			return err
		}
		line := strings.TrimSpace(string(lineBytes))
		if line == delimiter+"--" {
			return io.EOF
		}
		if line != delimiter {
			continue
		}
		header, err := readHeader(reader)
		if err != nil {
			return err
		}
		var data []byte
		length, lengthErr := strconv.Atoi(header.Get("Content-Length"))
		if header.Get("Content-Length") != "" && (lengthErr != nil || length < 0 || length > 8<<20) {
			return ErrStream
		}
		switch {
		case lengthErr == nil && length >= 0 && length <= 8<<20:
			if length > maxPart {
				if _, err := io.CopyN(io.Discard, reader, int64(length)); err != nil {
					return err
				}
				continue
			}
			data = make([]byte, length)
			if _, err := io.ReadFull(reader, data); err != nil {
				return err
			}
		default:
			// Without a length the part ends at the next boundary line.
			for len(data) <= maxPart {
				peek, err := reader.Peek(len(delimiter))
				if err == nil && string(peek) == delimiter {
					break
				}
				chunk, err := readLine(reader, maxPart-len(data))
				data = append(data, chunk...)
				if err != nil {
					return err
				}
			}
			if len(data) > maxPart {
				continue
			}
		}
		mediaType, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
		var parsed alert
		var ok bool
		switch {
		case strings.Contains(mediaType, "json"):
			parsed, ok = parseJSON(data)
		case strings.Contains(mediaType, "xml") || mediaType == "" || strings.HasPrefix(mediaType, "text/"):
			parsed, ok = parseXML(data)
		}
		if ok {
			select {
			case parts <- parsed:
			case <-done:
				return context.Canceled
			}
		}
	}
}

func readLine(reader *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(chunk) > limit-len(line) {
			return nil, ErrStream
		}
		line = append(line, chunk...)
		if !errors.Is(err, bufio.ErrBufferFull) {
			return line, err
		}
	}
}

func readHeader(reader *bufio.Reader) (textproto.MIMEHeader, error) {
	var data []byte
	for {
		line, err := readLine(reader, maxPart-len(data))
		if err != nil {
			return nil, ErrStream
		}
		data = append(data, line...)
		if string(line) == "\r\n" || string(line) == "\n" {
			break
		}
	}
	header, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(data))).ReadMIMEHeader()
	if err != nil {
		return nil, ErrStream
	}
	return header, nil
}
func parseXML(data []byte) (alert, bool) {
	var parsed alert
	if xml.Unmarshal(data, &parsed) != nil || parsed.EventType == "" {
		return alert{}, false
	}
	// Smart and AcuSense alerts carry the object class and region in nested
	// elements whose position differs between firmware versions.
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	var current string
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch element := token.(type) {
		case xml.StartElement:
			current = element.Name.Local
		case xml.CharData:
			text := strings.TrimSpace(string(element))
			switch {
			case text == "":
			case strings.EqualFold(current, "targetType") || strings.EqualFold(current, "detectionTarget"):
				parsed.TargetTypes = appendBounded(parsed.TargetTypes, text)
			case strings.EqualFold(current, "regionID"):
				parsed.RegionIDs = appendBounded(parsed.RegionIDs, text)
			}
		case xml.EndElement:
			current = ""
		}
	}
	return parsed, true
}

func parseJSON(data []byte) (alert, bool) {
	var raw map[string]any
	if json.Unmarshal(data, &raw) != nil {
		return alert{}, false
	}
	parsed := alert{EventType: text(raw["eventType"]), EventState: text(raw["eventState"]), Description: text(raw["eventDescription"]), ChannelID: text(raw["channelID"]),
		DynChannelID: text(raw["dynChannelID"]), ActivePostCount: text(raw["activePostCount"]), DateTime: text(raw["dateTime"])}
	var walk func(any, int)
	walk = func(value any, depth int) {
		if depth > 6 {
			return
		}
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				switch strings.ToLower(key) {
				case "targettype", "detectiontarget":
					parsed.TargetTypes = appendBounded(parsed.TargetTypes, text(child))
				case "regionid":
					parsed.RegionIDs = appendBounded(parsed.RegionIDs, text(child))
				}
				walk(child, depth+1)
			}
		case []any:
			for _, child := range value {
				walk(child, depth+1)
			}
		}
	}
	walk(raw, 0)
	return parsed, parsed.EventType != ""
}

func text(value any) string {
	switch value := value.(type) {
	case string:
		return clean(value)
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	}
	return ""
}

func appendBounded(values []string, value string) []string {
	value = clean(value)
	if value == "" || len(values) >= 8 {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func clean(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 64 {
		value = value[:64]
	}
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value)
}
