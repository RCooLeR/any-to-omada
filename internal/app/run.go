package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/cameraevents"
	"github.com/RCooLeR/any-to-omada/internal/camerartsp"
	"github.com/RCooLeR/any-to-omada/internal/config"
	"github.com/RCooLeR/any-to-omada/internal/eventstore"
	"github.com/RCooLeR/any-to-omada/internal/omadafront"
	"github.com/RCooLeR/any-to-omada/internal/onvifoutput"
	"github.com/RCooLeR/any-to-omada/internal/onvifptz"
	"github.com/RCooLeR/any-to-omada/internal/tpmarker"
)

// Version is the standalone service version, separate from OmadaNvrBridge.
const Version = "0.3.0"

type camera struct {
	cfg      config.Camera
	front    *omadafront.Server
	media    *camerartsp.Server
	server   *http.Server
	listener net.Listener
	tls      *tls.Config
	callback *callback
	ptz      *onvifptz.Controller
	relay    *onvifoutput.Relay
}

type cameraStatus struct {
	ID                  string             `json:"id"`
	Enabled             bool               `json:"enabled"`
	Verified            bool               `json:"verified"`
	SourceID            string             `json:"source_id"`
	SourceIndex         int                `json:"source_index"`
	Lens                string             `json:"lens"`
	AdvertisedIP        string             `json:"advertised_ip"`
	LogicalRecorderIP   string             `json:"logical_recorder_ip"`
	NativeOmadaReady    bool               `json:"native_omada_ready"`
	NativeAlarmDelivery string             `json:"native_alarm_delivery"`
	PTZControl          string             `json:"ptz_control"`
	PTZ                 *onvifptz.Status   `json:"ptz,omitempty"`
	Management          *omadafront.Status `json:"management,omitempty"`
	Media               *camerartsp.Status `json:"media,omitempty"`
	Callback            *callbackStatus    `json:"callback,omitempty"`
}

// Run starts one event worker per enabled physical source and two shared media
// workers per enabled lens. It runs until cancelled; camera outages are retried.
func Run(parent context.Context, cfg config.Config, logger *slog.Logger) (runErr error) {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	passwords, accountPasswords := map[string]string{}, map[string]string{}
	secrets := []string{}
	for _, source := range cfg.Sources {
		if !source.Enabled {
			continue
		}
		password, err := source.Account.Resolve()
		if err != nil {
			return errors.New("resolve source credentials failed")
		}
		passwords[source.ID] = password
		secrets = append(secrets, password)
	}
	for _, camera := range cfg.Cameras {
		if !camera.Enabled {
			continue
		}
		password, err := camera.Account.Resolve()
		if err != nil {
			return errors.New("resolve virtual camera credentials failed")
		}
		accountPasswords[camera.ID] = password
		secrets = append(secrets, password)
	}
	store, err := eventstore.Open(cfg.Storage.Directory, cfg.Storage.SegmentBytes, cfg.Storage.Segments, secrets)
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, store.Close()) }()
	sources := make([]*source, 0, len(cfg.Sources))
	sourceConfigs := map[string]config.Source{}
	sourceWorkers := map[string]*source{}
	for _, configured := range cfg.Sources {
		worker := newSource(configured, passwords[configured.ID], cfg.Cameras, store, cancel)
		sources = append(sources, worker)
		sourceWorkers[configured.ID] = worker
		sourceConfigs[configured.ID] = configured
	}
	cameras := []*camera{}
	var wg sync.WaitGroup
	control := httpServer(nil)
	control.WriteTimeout = 30 * time.Second
	control.BaseContext = func(net.Listener) context.Context { return ctx }
	controls := map[string]*cameraControls{}
	controlGates := map[string]*sourceControlGate{}
	finishControls := func() {}
	defer func() {
		cancel(nil)
		// Cancel test pulses, then allow their bounded output restoration to
		// finish before the process releases the source controllers.
		_ = control.Close()
		finishControls()
		for _, camera := range cameras {
			if camera.server != nil {
				_ = camera.server.Close()
			}
			if camera.listener != nil {
				_ = camera.listener.Close()
			}
			if camera.media != nil {
				camera.media.Close()
			}
			if camera.callback != nil {
				camera.callback.close()
			}
			if camera.ptz != nil {
				camera.ptz.Close()
			}
			if camera.relay != nil {
				camera.relay.Close()
			}
		}
		wg.Wait()
	}()
	// Validate every enabled TLS identity and bind management listeners before
	// starting source authentication. Cleanup owns any later partial startup.
	for _, configured := range cfg.Cameras {
		cam := &camera{cfg: configured}
		cameras = append(cameras, cam)
		if !configured.Enabled {
			continue
		}
		certificate, err := tls.LoadX509KeyPair(configured.TLSCertificateFile, configured.TLSKeyFile)
		if err != nil {
			return errors.New("load virtual camera TLS identity failed")
		}
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil || leaf.VerifyHostname(configured.AdvertisedIP) != nil || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
			return errors.New("virtual camera TLS identity must be current and include its advertised IP")
		}
		cam.tls = &tls.Config{MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true, Certificates: []tls.Certificate{certificate}}
		cam.callback = newCallback(ctx, configured.ID, configured.AdvertisedIP, logger.With("camera_id", configured.ID))
		if err := cam.callback.configureCredentials(configured.Account.Username, accountPasswords[configured.ID]); err != nil {
			return errors.New("initialize native callback credentials failed")
		}
		var ptz omadafront.PTZ
		if configured.PTZ != nil {
			source := sourceConfigs[configured.SourceID]
			cam.ptz, err = newPTZ(configured, source, passwords[source.ID], logger.With("camera_id", configured.ID))
			if err != nil {
				return errors.New("initialize virtual camera PTZ failed")
			}
			ptz = ptzAdapter{controller: cam.ptz, logger: logger.With("camera_id", configured.ID)}
		}
		cam.front, err = omadafront.New(omadafront.Config{Username: configured.Account.Username, Password: accountPasswords[configured.ID], IP: configured.AdvertisedIP, MAC: cam.callback.identity.MAC, Logger: logger.With("camera_id", configured.ID), StartCallback: cam.callback.register, StopCallback: cam.callback.stop,
			Metadata: func() omadafront.Metadata { return cameraMetadata(cam, sourceWorkers[configured.SourceID]) }, RTSPDigest: true,
			ClientCounts: func() (int, int) { return cameraClientCounts(cam) }, Compatibility: compatibility(configured.Compatibility), PTZ: ptz})
		if err != nil {
			return errors.New("initialize virtual management failed")
		}
		cam.callback.passthrough = cam.front.Passthrough
		cam.callback.allow = cam.front.EventAllowed
		cam.server = httpServer(cam.front)
		cam.listener, err = net.Listen("tcp", configured.ManagementAddress)
		if err != nil {
			return fmt.Errorf("bind virtual management: %w", err)
		}
		source := sourceConfigs[configured.SourceID]
		if controlGates[source.ID] == nil {
			controlGates[source.ID] = &sourceControlGate{busy: make(chan struct{}, 1)}
		}
		controls[configured.ID] = prepareControls(cam, source, passwords[source.ID], controlGates[source.ID])
		u, _ := config.StreamURL(configured.MainURL, source.Host)
		port, _ := strconv.Atoi(u.Port())
		cam.media, err = camerartsp.New(camerartsp.Config{Address: configured.RTSPAddress, AllowedClientIPs: configured.AllowedTransportPeers, UpstreamIP: source.Host, UpstreamPort: port, MainURL: configured.MainURL, SubURL: configured.SubURL, Username: source.Account.Username, Password: passwords[source.ID],
			VirtualUsername: configured.Account.Username, VirtualPassword: accountPasswords[configured.ID], MaxClients: 8, RetryMax: 5 * time.Minute,
			Marker: markerSource(configured.Compatibility, cam.callback)}, logger.With("camera_id", configured.ID))
		if err != nil {
			return errors.New("initialize virtual media failed")
		}
	}
	callbacks := make(map[string]*callback, len(cameras))
	for _, camera := range cameras {
		if camera.callback != nil {
			callbacks[camera.cfg.ID] = camera.callback
		}
	}
	for _, source := range sources {
		source.disconnected = func(id string) {
			if worker := callbacks[id]; worker != nil {
				worker.sourceDisconnected()
			}
		}
		source.deliver = func(id string, event cameraevents.Event) string {
			if worker := callbacks[id]; worker != nil {
				return worker.send(event)
			}
			return "unrouted"
		}
	}
	controlListener, err := net.Listen("tcp", cfg.ControlAddress)
	if err != nil {
		return errors.New("bind loopback control listener failed")
	}
	defer controlListener.Close()
	started := time.Now().UTC()
	snapshot := func() any {
		sourceStatuses := make([]sourceStatus, 0, len(sources))
		cameraStatuses := make([]cameraStatus, 0, len(cameras))
		anyCallbackReady := false
		for _, source := range sources {
			sourceStatuses = append(sourceStatuses, source.snapshot())
		}
		for _, camera := range cameras {
			status := cameraStatus{ID: camera.cfg.ID, Enabled: camera.cfg.Enabled, Verified: camera.cfg.Verified, SourceID: camera.cfg.SourceID, SourceIndex: camera.cfg.SourceIndex, Lens: camera.cfg.Lens, AdvertisedIP: camera.cfg.AdvertisedIP, LogicalRecorderIP: camera.cfg.RecorderIP, NativeAlarmDelivery: "awaiting_registration", PTZControl: "unsupported"}
			if camera.front != nil {
				management := camera.front.Status()
				status.Management = &management
			}
			if camera.media != nil {
				media := camera.media.Status()
				status.Media = &media
			}
			if camera.ptz != nil {
				ptzStatus := camera.ptz.Status()
				status.PTZ, status.PTZControl = &ptzStatus, "onvif_unverified"
			}
			if camera.callback != nil {
				callback := camera.callback.snapshot()
				status.Callback = &callback
				status.NativeAlarmDelivery = callback.State
				status.NativeOmadaReady = callback.State == "connected"
				anyCallbackReady = anyCallbackReady || status.NativeOmadaReady
			}
			cameraStatuses = append(cameraStatuses, status)
		}
		return map[string]any{"version": Version, "started_utc": started, "native_omada_ready": anyCallbackReady, "native_alarm_delivery": "implemented_unverified", "recorder_history_verified": false, "sources": sourceStatuses, "cameras": cameraStatuses, "limitation": "native_omada_ready indicates an authenticated callback transport, not verified enrollment or history acceptance; unmapped source classifications remain unsupported and PTZ control is unverified"}
	}
	mux := http.NewServeMux()
	finishControls = registerControls(mux, controls)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"alive": true, "version": Version})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		status := snapshot().(map[string]any)
		code := http.StatusServiceUnavailable
		if status["native_omada_ready"] == true {
			code = http.StatusOK
		}
		writeJSON(w, code, status)
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, snapshot()) })
	control.Handler = mux
	serve := func(server *http.Server, listener net.Listener) {
		wg.Go(func() {
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				cancel(errors.New("translator listener failed"))
			}
		})
	}
	for _, camera := range cameras {
		if !camera.cfg.Enabled {
			continue
		}
		if err := camera.media.Start(ctx); err != nil {
			return errors.New("start virtual media failed")
		}
		serve(camera.server, tls.NewListener(restrict(camera.listener, camera.cfg.AllowedTransportPeers), camera.tls))
	}
	serve(control, controlListener)
	for _, source := range sources {
		if source.cfg.Enabled {
			wg.Go(func() { source.run(ctx) })
		}
	}
	logger.Info("translator listening", "version", Version, "native_omada_ready", false, "native_alarm_delivery", "implemented_unverified")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if parent.Err() != nil {
				return nil
			}
			return context.Cause(ctx)
		case <-ticker.C:
			if err := store.Sync(); err != nil {
				return err
			}
		}
	}
}

// markerSource returns the in-stream marker state when the experiment is enabled.
func markerSource(cfg config.Compatibility, worker *callback) func() tpmarker.State {
	if !cfg.InStreamMarkers || worker == nil {
		return nil
	}
	return worker.markerState
}

// compatibility maps the configured experiment options; the zero value keeps
// implemented features and source facts only.
func compatibility(cfg config.Compatibility) omadafront.Compatibility {
	result := omadafront.Compatibility{ObservedModuleSpec: cfg.ModuleSpecProfile == "omada-ipc-observed", AdvertiseVHTTPD: cfg.AdvertiseVHTTPD,
		ExtendedVideoFields: cfg.ExtendedVideoFields, ExtendedIdentity: cfg.ExtendedIdentity, ManufacturerName: cfg.ManufacturerName, EncodeHTTPStrings: cfg.EncodeHTTPStrings,
		PTZModuleSpecKeys: cfg.PTZModuleSpecKeys}
	if cfg.Network != nil {
		result.Netmask, result.Gateway, result.DNS = cfg.Network.Netmask, cfg.Network.Gateway, cfg.Network.DNS
	}
	return result
}

func httpServer(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data) // Disconnected clients own response-write errors.
}
