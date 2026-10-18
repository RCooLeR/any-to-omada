package camerartsp

import (
	"context"
	"errors"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/tpmarker"
	"github.com/bluenviron/gortsplib/v5"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
	"github.com/bluenviron/gortsplib/v5/pkg/description"
	"github.com/bluenviron/gortsplib/v5/pkg/format"
	"github.com/bluenviron/gortsplib/v5/pkg/liberrors"
	"github.com/pion/rtp"
)

type failure struct {
	reason                    string
	authentication, permanent bool
}

func (e *failure) Error() string { return e.reason }

func classify(stage string, err error) *failure {
	result := &failure{reason: stage + "_failed"}
	if _, ok := errors.AsType[liberrors.ErrClientAuthSetup](err); ok {
		return &failure{reason: "authentication_negotiation_failed", permanent: true}
	}
	if status, ok := errors.AsType[liberrors.ErrClientBadStatusCode](err); ok {
		switch status.Code {
		case base.StatusUnauthorized, base.StatusForbidden:
			result.reason = "authentication_rejected"
			result.authentication = true
		case base.StatusNotFound, base.StatusBadRequest, base.StatusUnsupportedTransport:
			result.reason = "profile_configuration_rejected"
			result.permanent = true
		}
	}
	return result
}

func (s *Server) runProfile(p *profile) {
	delay := s.cfg.RetryMin
	for s.ctx.Err() == nil {
		s.mu.Lock()
		p.status.State = "connecting"
		p.status.Reason = ""
		p.status.NextRetryUTC = time.Time{}
		p.status.Attempts++
		s.mu.Unlock()
		ready, err := s.attempt(p)
		if err.authentication {
			s.mu.Lock()
			s.authFailed = true
			s.mu.Unlock()
			s.cancel()
		}
		if s.ctx.Err() != nil {
			break
		}
		if err.permanent {
			s.mu.Lock()
			p.status.State = "configuration_error"
			p.status.Reason = err.reason
			s.mu.Unlock()
			return
		}
		if ready {
			delay = s.cfg.RetryMin
		}
		s.mu.Lock()
		p.status.State = "retry_wait"
		p.status.Reason = err.reason
		p.status.NextRetryUTC = time.Now().Add(delay).UTC()
		s.mu.Unlock()
		s.logger.Warn("camera RTSP profile disconnected", "profile", p.name, "reason", err.reason, "retry_seconds", delay.Seconds())
		timer := time.NewTimer(delay)
		select {
		case <-s.ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		delay = min(delay*2, s.cfg.RetryMax)
	}
	s.mu.Lock()
	if s.authFailed {
		p.status.State = "authentication_failed"
		p.status.Reason = "authentication_rejected"
	} else {
		p.status.State = "stopped"
		p.status.Reason = ""
	}
	p.status.NextRetryUTC = time.Time{}
	s.mu.Unlock()
}

func (s *Server) attempt(p *profile) (bool, *failure) {
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	protocol := gortsplib.ProtocolTCP
	u, _ := base.ParseURL(p.url) // New validated both fixed URLs.
	u.User = url.UserPassword(s.cfg.Username, s.cfg.Password)
	client := &gortsplib.Client{Scheme: u.Scheme, Host: u.Host, Protocol: &protocol,
		ReadTimeout: s.cfg.ReadTimeout, WriteTimeout: s.cfg.ConnectTimeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != s.cfg.origin() {
				return nil, errors.New("RTSP upstream origin refused")
			}
			return (&net.Dialer{Timeout: s.cfg.ConnectTimeout}).DialContext(ctx, network, address)
		},
		OnTransportSwitch: func(error) {}, OnDecodeError: func(error) {}, OnPacketsLost: func(uint64) {},
	}
	if err := client.Start(); err != nil {
		return false, classify("start", err)
	}
	defer client.Close()
	stopCancel := context.AfterFunc(ctx, client.Close)
	defer stopCancel()
	startup := time.AfterFunc(s.cfg.ConnectTimeout, cancel)
	defer startup.Stop()
	desc, _, err := client.Describe(u)
	if err != nil {
		return false, classify("describe", err)
	}
	if !s.validDescription(desc) {
		return false, &failure{reason: "description_origin_or_tracks_refused", permanent: true}
	}
	if err = client.SetupAll(desc.BaseURL, desc.Medias); err != nil {
		return false, classify("setup", err)
	}
	// The upstream title/BaseURL are not advertised. ServerStream generates local
	// track controls while keeping these media pointers for packet forwarding.
	stream := &gortsplib.ServerStream{Server: s.server, Desc: &description.Session{Title: "Camera proxy", Medias: desc.Medias}}
	if err = stream.Initialize(); err != nil {
		return false, classify("stream", err)
	}
	defer func() {
		// Join the producer before retiring its stream so no packet callback
		// can race stream teardown or the next generation's initialization.
		client.Close()
		s.mu.Lock()
		if p.stream == stream {
			p.stream = nil
			p.video = VideoMetadata{}
		}
		s.mu.Unlock()
		stream.Close()
	}()
	first := make(chan struct{})
	var once sync.Once
	inserters := markerInserters(desc.Medias, s.cfg.Marker)
	client.OnPacketRTPAny(func(media *description.Media, _ format.Format, packet *rtp.Packet) {
		p.packets.Add(1)
		p.lastPacket.Store(time.Now().UnixNano())
		if media.Type == description.MediaTypeVideo {
			once.Do(func() { close(first) })
		}
		packets := []*rtp.Packet{packet}
		if inserter := inserters[media]; inserter != nil {
			packets = inserter.process(packet)
		}
		ntp, hasNTP := client.PacketNTP(media, packet)
		for _, out := range packets {
			var writeErr error
			if hasNTP {
				writeErr = stream.WritePacketRTPWithNTP(media, out, ntp)
			} else {
				writeErr = stream.WritePacketRTP(media, out)
			}
			if writeErr != nil {
				cancel()
				return
			}
		}
	})
	if _, err = client.Play(nil); err != nil {
		return false, classify("play", err)
	}
	select {
	case <-first:
	case <-ctx.Done():
		return false, &failure{reason: "first_video_timeout_or_cancelled"}
	}
	startup.Stop()
	if ctx.Err() != nil {
		return false, &failure{reason: "startup_cancelled"}
	}
	video := descriptionVideoMetadata(desc)
	s.mu.Lock()
	if s.closed || s.authFailed {
		s.mu.Unlock()
		return false, &failure{reason: "cancelled"}
	}
	p.stream = stream
	p.video = video
	p.status.State = "ready"
	p.status.Reason = ""
	s.mu.Unlock()
	s.logger.Info("camera RTSP profile ready", "profile", p.name)
	err = client.Wait()
	return true, classify("connection", err)
}

// markerInserters creates one inserter per single-format H.264/H.265 video
// media when marker units are configured.
func markerInserters(medias []*description.Media, state func() tpmarker.State) map[*description.Media]*markerInserter {
	result := map[*description.Media]*markerInserter{}
	if state == nil {
		return result
	}
	for _, media := range medias {
		if media == nil || media.Type != description.MediaTypeVideo || len(media.Formats) != 1 {
			continue
		}
		codec := ""
		switch media.Formats[0].(type) {
		case *format.H264:
			codec = "H264"
		case *format.H265:
			codec = "H265"
		}
		if inserter := newMarkerInserter(codec, state); inserter != nil {
			result[media] = inserter
		}
	}
	return result
}

func (s *Server) validDescription(desc *description.Session) bool {
	if desc == nil || !s.cfg.sameOrigin(desc.BaseURL) || len(desc.Medias) == 0 || len(desc.Medias) > 8 {
		return false
	}
	hasVideo := false
	for _, media := range desc.Medias {
		if media == nil || media.IsBackChannel || len(media.Formats) == 0 {
			return false
		}
		// gortsplib deliberately replaces an absolute control URL's host with
		// Content-Base. Check the received value before that normalization.
		raw, err := url.Parse(media.Control)
		if err != nil || ((raw.IsAbs() || raw.Host != "") && !s.cfg.sameOrigin((*base.URL)(raw))) {
			return false
		}
		control, err := media.URL(desc.BaseURL)
		if err != nil || !s.cfg.sameOrigin(control) {
			return false
		}
		if media.Type == description.MediaTypeVideo {
			hasVideo = true
		}
	}
	return hasVideo
}
