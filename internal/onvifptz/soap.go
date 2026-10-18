// Package onvifptz drives one physical lens through its source camera's ONVIF
// PTZ service: continuous pan, tilt and zoom with a bounded automatic stop,
// and preset listing, recall, saving and removal. It changes no other camera
// setting. Errors are fixed values without camera responses or credentials.
package onvifptz

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
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	devicePath      = "/onvif/device_service"
	deviceNamespace = "http://www.onvif.org/ver10/device/wsdl"
	mediaNamespace  = "http://www.onvif.org/ver10/media/wsdl"
	ptzNamespace    = "http://www.onvif.org/ver20/ptz/wsdl"
	soapNamespace   = "http://www.w3.org/2003/05/soap-envelope"
	schemaNamespace = "http://www.onvif.org/ver10/schema"
	maxSOAPBytes    = 1024 * 1024
)

var (
	// ErrUnavailable identifies sanitized transport, protocol and discovery failures.
	ErrUnavailable = errors.New("ptz unavailable")
	// ErrAuthentication includes the cooldown after rejected credentials.
	ErrAuthentication = errors.New("ptz authentication unavailable")
	// ErrUnsupported means the lens or camera lacks the requested operation.
	ErrUnsupported = errors.New("ptz unsupported")
	// ErrRefused means the camera answered the operation with a SOAP fault.
	ErrRefused = errors.New("ptz request refused")
)

type soapClient struct {
	base, username, password string
	http                     *http.Client
	// authMu protects the cooldown, clock offset and bounded Digest nonce
	// state; network I/O never holds it.
	authMu       sync.Mutex
	nonces       map[digestNonceKey]*digestNonceState
	nonceOrder   []digestNonceKey
	blockedUntil time.Time
	clockOffset  time.Duration
	now          func() time.Time
}

func newSOAP(host string, port int, username, password string) *soapClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxConnsPerHost = 4
	transport.MaxIdleConnsPerHost = 2
	transport.ResponseHeaderTimeout = 3 * time.Second
	return &soapClient{base: fmt.Sprintf("http://%s:%d", host, port), username: username, password: password, now: time.Now,
		http: &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// call sends one SOAP operation. Authentication uses a WS-Security
// UsernameToken on every request and answers an HTTP Digest challenge once,
// so cameras requiring either scheme work. Rejected credentials start a
// cooldown that protects the shared source account from lockout.
func (c *soapClient) call(ctx context.Context, path, namespace, operation, content string, out any) error {
	return c.exchange(ctx, true, path, namespace, operation, content, out)
}

func (c *soapClient) exchange(ctx context.Context, authenticated bool, path, namespace, operation, content string, out any) (resultErr error) {
	stage := "request"
	defer func() {
		if resultErr != nil {
			resultErr = fmt.Errorf("ptz %s %s: %w", operation, stage, resultErr)
		}
	}()
	c.authMu.Lock()
	blocked := c.now().Before(c.blockedUntil)
	c.authMu.Unlock()
	if blocked {
		stage = "authentication_cooldown"
		return ErrAuthentication
	}
	payload, err := c.envelope(authenticated, namespace, operation, content)
	if err != nil {
		return err
	}
	status, authenticate, data, err := c.request(ctx, path, namespace, operation, payload, nil)
	if err != nil {
		return err
	}
	if status == http.StatusUnauthorized && !authenticated {
		return ErrUnavailable
	}
	if status == http.StatusUnauthorized {
		stage = "challenge_parse"
		parsed, err := parseDigest(authenticate)
		if err != nil {
			c.blockAuth()
			return ErrAuthentication
		}
		stage = "authenticated_request"
		// A fresh UsernameToken nonce: cameras reject a replayed one.
		if payload, err = c.envelope(true, namespace, operation, content); err != nil {
			return err
		}
		status, authenticate, data, err = c.request(ctx, path, namespace, operation, payload, &parsed)
		if err != nil {
			return err
		}
		if status == http.StatusUnauthorized {
			fresh, parseErr := parseDigest(authenticate)
			if parseErr == nil && fresh.stale && fresh.nonce != parsed.nonce && fresh.realm == parsed.realm && fresh.algorithm == parsed.algorithm {
				// An explicit stale rejection permits one nonce renewal, never a
				// replay after an uncertain transport or a successful action.
				stage = "stale_nonce_request"
				if payload, err = c.envelope(true, namespace, operation, content); err != nil {
					return err
				}
				status, _, data, err = c.request(ctx, path, namespace, operation, payload, &fresh)
				if err != nil {
					return err
				}
			}
		}
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		stage = "authentication_rejected"
		c.blockAuth()
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
	if response.XMLName.Local == "Fault" && response.XMLName.Space == soapNamespace {
		stage = "fault"
		// Fault text is camera-controlled; only a fixed authentication class
		// is derived from it and nothing of it is returned or logged.
		text := strings.ToLower(string(response.Content))
		if strings.Contains(text, "notauthorized") || strings.Contains(text, "failedauthentication") {
			c.blockAuth()
			return ErrAuthentication
		}
		return ErrRefused
	}
	if status != http.StatusOK {
		stage = "http_status"
		return ErrUnavailable
	}
	if response.XMLName.Local != operation+"Response" || response.XMLName.Space != namespace {
		return ErrUnavailable
	}
	if out != nil && xml.Unmarshal(append(append([]byte("<result>"), response.Content...), []byte("</result>")...), out) != nil {
		return ErrUnavailable
	}
	return nil
}

func (c *soapClient) envelope(authenticated bool, namespace, operation, content string) ([]byte, error) {
	header := ""
	if authenticated {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, ErrUnavailable
		}
		c.authMu.Lock()
		created := c.now().Add(c.clockOffset).UTC().Format("2006-01-02T15:04:05Z")
		c.authMu.Unlock()
		sum := sha1.Sum(append(append(nonce[:], created...), c.password...))
		header = `<s:Header><wsse:Security s:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">` +
			`<wsse:UsernameToken><wsse:Username>` + xmlText(c.username) + `</wsse:Username>` +
			`<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">` + base64.StdEncoding.EncodeToString(sum[:]) + `</wsse:Password>` +
			`<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">` + base64.StdEncoding.EncodeToString(nonce[:]) + `</wsse:Nonce>` +
			`<wsu:Created>` + created + `</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header>`
	}
	return []byte(`<s:Envelope xmlns:s="` + soapNamespace + `" xmlns:t="` + namespace + `" xmlns:tt="` + schemaNamespace + `">` + header +
		`<s:Body><t:` + operation + `>` + content + `</t:` + operation + `></s:Body></s:Envelope>`), nil
}

func (c *soapClient) request(ctx context.Context, path, namespace, operation string, payload []byte, challenge *digestChallenge) (int, string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(payload))
	if err != nil {
		return 0, "", nil, ErrUnavailable
	}
	req.Header.Set("Content-Type", `application/soap+xml; charset=utf-8; action="`+namespace+`/`+operation+`"`)
	if challenge != nil {
		auth, err := c.authorization(*challenge, path)
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

// syncClock reads the camera clock without credentials so UsernameToken
// creation times match the camera, which rejects skewed tokens.
func (c *soapClient) syncClock(ctx context.Context) {
	var response struct {
		SystemDateAndTime struct {
			UTCDateTime struct {
				Date struct{ Year, Month, Day int }
				Time struct{ Hour, Minute, Second int }
			}
		}
	}
	sent := c.now()
	if c.exchange(ctx, false, devicePath, deviceNamespace, "GetSystemDateAndTime", "", &response) != nil {
		return
	}
	date, clock := response.SystemDateAndTime.UTCDateTime.Date, response.SystemDateAndTime.UTCDateTime.Time
	if date.Year < 2000 || date.Month < 1 || date.Month > 12 || date.Day < 1 || date.Day > 31 || clock.Hour > 23 || clock.Minute > 59 || clock.Second > 60 {
		return
	}
	camera := time.Date(date.Year, time.Month(date.Month), date.Day, clock.Hour, clock.Minute, clock.Second, 0, time.UTC)
	c.authMu.Lock()
	c.clockOffset = camera.Sub(sent)
	c.authMu.Unlock()
}

func (c *soapClient) blockAuth() {
	c.authMu.Lock()
	// Long enough that a wrong password cannot lock the shared source account.
	c.blockedUntil = c.now().Add(15 * time.Minute)
	c.authMu.Unlock()
}

func xmlText(value string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(value)) // bytes.Buffer writes cannot fail.
	return b.String()
}
