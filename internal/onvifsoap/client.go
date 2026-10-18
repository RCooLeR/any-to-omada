// Package onvifsoap is a bounded ONVIF SOAP 1.2 client for one camera. It
// authenticates with a WS-Security UsernameToken on every request and answers
// one HTTP Digest challenge, so cameras requiring either scheme work. Errors
// are fixed values without camera responses or credentials.
package onvifsoap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1" // WS-Security UsernameToken PasswordDigest is defined over SHA-1.
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/httpdigest"
)

const (
	DevicePath      = "/onvif/device_service"
	DeviceNamespace = "http://www.onvif.org/ver10/device/wsdl"
	MediaNamespace  = "http://www.onvif.org/ver10/media/wsdl"
	EventsNamespace = "http://www.onvif.org/ver10/events/wsdl"
	NotifyNamespace = "http://docs.oasis-open.org/wsn/b-2"
	SOAPNamespace   = "http://www.w3.org/2003/05/soap-envelope"
	SchemaNamespace = "http://www.onvif.org/ver10/schema"
	maxSOAPBytes    = 1024 * 1024
)

var (
	// ErrUnavailable identifies sanitized transport, protocol and discovery failures.
	ErrUnavailable = errors.New("onvif unavailable")
	// ErrAuthentication includes the cooldown after rejected credentials.
	ErrAuthentication = errors.New("onvif authentication unavailable")
	// ErrRefused means the camera answered the operation with a SOAP fault.
	ErrRefused = errors.New("onvif request refused")
)

// Client talks to one camera endpoint. It is safe for concurrent use.
type Client struct {
	base               *url.URL
	username, password string
	http               *http.Client
	digest             *httpdigest.Authorizer
	// mu protects the cooldown and clock offset; network I/O never holds it.
	mu           sync.Mutex
	blockedUntil time.Time
	clockOffset  time.Duration
	now          func() time.Time
}

// New prepares a plain-HTTP client for host:port; it contacts nothing.
func New(host string, port int, username, password string, timeout time.Duration) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxConnsPerHost = 4
	transport.MaxIdleConnsPerHost = 2
	transport.ResponseHeaderTimeout = timeout
	base := &url.URL{Scheme: "http", Host: net.JoinHostPort(host, strconv.Itoa(port))}
	return &Client{base: base, username: username, password: password, now: time.Now,
		digest: &httpdigest.Authorizer{Username: username, Password: password},
		http:   &http.Client{Transport: transport, Timeout: timeout + time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Close releases this client's idle camera connections after a capture ends.
func (c *Client) Close() { c.http.CloseIdleConnections() }

// Request describes one SOAP operation. Address is a path on the camera or an
// absolute URL on the same host and port; Action defaults to Namespace/Operation.
type Request struct {
	Address, Namespace, Operation, Action, Content string
	// Addressing adds WS-Addressing Action and To headers, which subscription
	// managers of several cameras require.
	Addressing bool
	// Anonymous sends no credentials, for GetSystemDateAndTime.
	Anonymous bool
	// Headers are extra SOAP header elements, such as a subscription's echoed
	// WS-Addressing reference parameters. The caller builds them safely.
	Headers string
}

// Call sends an operation to a service path.
func (c *Client) Call(ctx context.Context, path, namespace, operation, content string, out any) error {
	return c.Do(ctx, Request{Address: path, Namespace: namespace, Operation: operation, Content: content}, out)
}

// Do sends one operation and decodes its single response element into out.
func (c *Client) Do(ctx context.Context, request Request, out any) (resultErr error) {
	stage := "request"
	defer func() {
		if resultErr != nil {
			resultErr = fmt.Errorf("onvif %s %s: %w", request.Operation, stage, resultErr)
		}
	}()
	target, err := c.Resolve(request.Address)
	if err != nil {
		return err
	}
	if request.Action == "" {
		request.Action = request.Namespace + "/" + request.Operation
	}
	c.mu.Lock()
	blocked := c.now().Before(c.blockedUntil)
	c.mu.Unlock()
	if blocked {
		stage = "authentication_cooldown"
		return ErrAuthentication
	}
	payload, err := c.envelope(request, target, !request.Anonymous)
	if err != nil {
		return err
	}
	status, authenticate, data, err := c.post(ctx, target, request.Action, payload, nil)
	if err != nil {
		return err
	}
	if status == http.StatusUnauthorized && request.Anonymous {
		return ErrUnavailable
	}
	if status == http.StatusUnauthorized {
		stage = "challenge_parse"
		parsed, err := httpdigest.Parse(authenticate)
		if err != nil {
			c.block()
			return ErrAuthentication
		}
		stage = "authenticated_request"
		// A fresh UsernameToken nonce: cameras reject a replayed one.
		if payload, err = c.envelope(request, target, true); err != nil {
			return err
		}
		status, authenticate, data, err = c.post(ctx, target, request.Action, payload, &parsed)
		if err != nil {
			return err
		}
		if status == http.StatusUnauthorized {
			fresh, parseErr := httpdigest.Parse(authenticate)
			if parseErr == nil && fresh.Stale && fresh.Nonce != parsed.Nonce && fresh.Realm == parsed.Realm && fresh.Algorithm == parsed.Algorithm {
				// An explicit stale rejection permits one nonce renewal, never a
				// replay after an uncertain transport or a successful action.
				stage = "stale_nonce_request"
				if payload, err = c.envelope(request, target, true); err != nil {
					return err
				}
				status, _, data, err = c.post(ctx, target, request.Action, payload, &fresh)
				if err != nil {
					return err
				}
			}
		}
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		stage = "authentication_rejected"
		c.block()
		return ErrAuthentication
	}
	stage = "response_parse"
	var envelope struct {
		XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"`
		Body    struct {
			Elements []struct {
				XMLName xml.Name
				Content []byte `xml:",innerxml"`
			} `xml:",any"`
		} `xml:"http://www.w3.org/2003/05/soap-envelope Body"`
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	if err := d.Decode(&envelope); err != nil || len(envelope.Body.Elements) != 1 {
		if status != http.StatusOK {
			stage = "http_status"
		}
		return ErrUnavailable
	}
	response := envelope.Body.Elements[0]
	if response.XMLName.Local == "Fault" && response.XMLName.Space == SOAPNamespace {
		stage = "fault"
		// Fault text is camera-controlled; only a fixed authentication class
		// is derived from it and nothing of it is returned or logged.
		text := strings.ToLower(string(response.Content))
		if strings.Contains(text, "notauthorized") || strings.Contains(text, "failedauthentication") {
			c.block()
			return ErrAuthentication
		}
		return ErrRefused
	}
	if status != http.StatusOK {
		stage = "http_status"
		return ErrUnavailable
	}
	if response.XMLName.Local != request.Operation+"Response" || response.XMLName.Space != request.Namespace {
		return ErrUnavailable
	}
	if out != nil && xml.Unmarshal(append(append([]byte("<result"+namespaceDeclarations(data)+">"), response.Content...), []byte("</result>")...), out) != nil {
		return ErrUnavailable
	}
	return nil
}

// namespaceDeclarations collects the prefixed xmlns declarations of the
// envelope, body and response element, so prefixes used inside the response
// still resolve to their namespaces after it is decoded on its own.
func namespaceDeclarations(data []byte) string {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	bindings := map[string]string{}
	declarations := func() string {
		prefixes := make([]string, 0, len(bindings))
		for prefix := range bindings {
			prefixes = append(prefixes, prefix)
		}
		sort.Strings(prefixes)
		var b strings.Builder
		for _, prefix := range prefixes {
			attribute := "xmlns"
			if prefix != "" {
				attribute += ":" + prefix
			}
			b.WriteString(" " + attribute + `="` + Text(bindings[prefix]) + `"`)
		}
		return b.String()
	}
	depth, inBody := 0, false
	for tokens := 0; tokens < 4096; tokens++ {
		token, err := decoder.RawToken()
		if err != nil {
			break
		}
		switch element := token.(type) {
		case xml.StartElement:
			depth++
			// Only the envelope, the body and the response element are in scope
			// of the response content; header elements are siblings.
			if depth == 1 || (depth == 2 && element.Name.Local == "Body") || (inBody && depth == 3) {
				for _, attr := range element.Attr {
					prefix := attr.Name.Local
					if attr.Name.Space == "" && prefix == "xmlns" {
						prefix = ""
					} else if attr.Name.Space != "xmlns" {
						continue
					}
					_, exists := bindings[prefix]
					if exists || len(bindings) < 32 {
						// A nearer declaration shadows an outer one, including
						// the default namespace used by unprefixed parameters.
						bindings[prefix] = attr.Value
					}
				}
			}
			if inBody && depth == 3 {
				return declarations()
			}
			if depth == 2 && element.Name.Local == "Body" {
				inBody = true
			}
		case xml.EndElement:
			depth--
		}
	}
	return declarations()
}

// Resolve accepts a path or an absolute plain-HTTP URL on the configured host
// and port, so a camera-supplied address cannot redirect credentials elsewhere.
func (c *Client) Resolve(address string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(address))
	if err != nil || u.User != nil || u.Fragment != "" || len(address) > 512 {
		return nil, ErrUnavailable
	}
	if !u.IsAbs() {
		// A network-path reference such as //another-camera/path has no
		// scheme but replaces the authority when resolved against the base.
		if u.Host != "" {
			return nil, ErrUnavailable
		}
		if !strings.HasPrefix(u.Path, "/") {
			return nil, ErrUnavailable
		}
		return c.base.ResolveReference(u), nil
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	if u.Scheme != "http" || u.Hostname() != c.base.Hostname() || port != c.base.Port() {
		return nil, ErrUnavailable
	}
	return u, nil
}

func (c *Client) envelope(request Request, target *url.URL, authenticated bool) ([]byte, error) {
	header := ""
	if request.Addressing {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil, ErrUnavailable
		}
		header += `<wsa:Action>` + Text(request.Action) + `</wsa:Action><wsa:MessageID>urn:uuid:` + uuid(id) + `</wsa:MessageID><wsa:To>` + Text(target.String()) + `</wsa:To>`
	}
	header += request.Headers
	if authenticated && c.username != "" {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, ErrUnavailable
		}
		c.mu.Lock()
		created := c.now().Add(c.clockOffset).UTC().Format("2006-01-02T15:04:05Z")
		c.mu.Unlock()
		sum := sha1.Sum(append(append(nonce[:], created...), c.password...))
		header += `<wsse:Security s:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">` +
			`<wsse:UsernameToken><wsse:Username>` + Text(c.username) + `</wsse:Username>` +
			`<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">` + base64.StdEncoding.EncodeToString(sum[:]) + `</wsse:Password>` +
			`<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">` + base64.StdEncoding.EncodeToString(nonce[:]) + `</wsse:Nonce>` +
			`<wsu:Created>` + created + `</wsu:Created></wsse:UsernameToken></wsse:Security>`
	}
	if header != "" {
		header = `<s:Header>` + header + `</s:Header>`
	}
	return []byte(`<s:Envelope xmlns:s="` + SOAPNamespace + `" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:t="` + request.Namespace + `" xmlns:tt="` + SchemaNamespace + `">` + header +
		`<s:Body><t:` + request.Operation + `>` + request.Content + `</t:` + request.Operation + `></s:Body></s:Envelope>`), nil
}

func uuid(b [16]byte) string {
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (c *Client) post(ctx context.Context, target *url.URL, action string, payload []byte, challenge *httpdigest.Challenge) (int, string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(payload))
	if err != nil {
		return 0, "", nil, ErrUnavailable
	}
	req.Header.Set("Content-Type", `application/soap+xml; charset=utf-8; action="`+action+`"`)
	if challenge != nil {
		auth, err := c.digest.Header(*challenge, http.MethodPost, target.RequestURI())
		if err != nil {
			return 0, "", nil, ErrAuthentication
		}
		req.Header.Set("Authorization", auth)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", nil, ErrUnavailable
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSOAPBytes+1))
	if err != nil || len(data) > maxSOAPBytes {
		return 0, "", nil, ErrUnavailable
	}
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate"), data, nil
}

// SyncClock reads the camera clock without credentials so UsernameToken
// creation times match the camera, which rejects skewed tokens.
func (c *Client) SyncClock(ctx context.Context) {
	var response struct {
		SystemDateAndTime struct {
			UTCDateTime struct {
				Date struct{ Year, Month, Day int }
				Time struct{ Hour, Minute, Second int }
			}
		}
	}
	sent := c.now()
	if c.Do(ctx, Request{Address: DevicePath, Namespace: DeviceNamespace, Operation: "GetSystemDateAndTime", Anonymous: true}, &response) != nil {
		return
	}
	date, clock := response.SystemDateAndTime.UTCDateTime.Date, response.SystemDateAndTime.UTCDateTime.Time
	if date.Year < 2000 || date.Month < 1 || date.Month > 12 || date.Day < 1 || date.Day > 31 || clock.Hour > 23 || clock.Minute > 59 || clock.Second > 60 {
		return
	}
	camera := time.Date(date.Year, time.Month(date.Month), date.Day, clock.Hour, clock.Minute, clock.Second, 0, time.UTC)
	c.mu.Lock()
	c.clockOffset = camera.Sub(sent)
	c.mu.Unlock()
}

// ServicePaths reads GetServices and returns the paths of the requested
// namespaces that live on this camera endpoint.
func (c *Client) ServicePaths(ctx context.Context, namespaces ...string) (map[string]string, error) {
	var services struct {
		Service []struct{ Namespace, XAddr string }
	}
	if err := c.Call(ctx, DevicePath, DeviceNamespace, "GetServices", "<t:IncludeCapability>false</t:IncludeCapability>", &services); err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, namespace := range namespaces {
		wanted[namespace] = true
	}
	paths := map[string]string{}
	for _, service := range services.Service {
		if !wanted[service.Namespace] {
			continue
		}
		if target, err := c.Resolve(service.XAddr); err == nil && len(target.Path) <= 128 && target.RawQuery == "" {
			paths[service.Namespace] = target.Path
		}
	}
	return paths, nil
}

func (c *Client) block() {
	c.mu.Lock()
	// Long enough that a wrong password cannot lock the shared source account.
	c.blockedUntil = c.now().Add(15 * time.Minute)
	c.mu.Unlock()
}

// Text escapes a value for XML character data or attributes.
func Text(value string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(value)) // bytes.Buffer writes cannot fail.
	return b.String()
}
