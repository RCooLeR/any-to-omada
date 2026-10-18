package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/config"
)

func TestRunStartsWithSharedSourceAndVirtualPassword(t *testing.T) {
	t.Setenv("TEST_SOURCE_PASSWORD", "synthetic-shared-camera-password")
	t.Setenv("TEST_VIRTUAL_PASSWORD", "synthetic-shared-camera-password")
	cfg, err := config.Load(filepath.Join("..", "..", "config.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Sources = cfg.Sources[:1]
	cfg.Cameras = cfg.Cameras[:1]
	cfg.Storage.Directory = t.TempDir()
	// All upstream attempts terminate at this local stub; no camera is contacted.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	defer func() { _ = upstream.Close(); <-upstreamDone }()
	_, port, _ := net.SplitHostPort(upstream.Addr().String())
	cfg.Sources[0].Enabled = true
	cfg.Sources[0].Host = "127.0.0.1"
	cfg.Sources[0].NativePort, _ = strconv.Atoi(port)
	cfg.Sources[0].Account = config.Account{Username: "fixture-source", PasswordEnv: "TEST_SOURCE_PASSWORD"}
	addresses := reserveLoopbackAddresses(t, 3)
	cfg.ControlAddress = addresses[0]
	camera := &cfg.Cameras[0]
	camera.Enabled = true
	camera.Verified = true
	camera.AdvertisedIP = "127.0.0.1"
	camera.ManagementAddress = addresses[1]
	camera.RTSPAddress = addresses[2]
	camera.MainURL = "rtsp://" + upstream.Addr().String() + "/main"
	camera.SubURL = "rtsp://" + upstream.Addr().String() + "/sub"
	camera.Account = config.Account{Username: "fixture-proxy", PasswordEnv: "TEST_VIRTUAL_PASSWORD"}
	camera.TLSCertificateFile, camera.TLSKeyFile = writeLoopbackTLSIdentity(t)
	ctx, cancel := context.WithCancel(t.Context())
	finished := make(chan struct{})
	var runErr error
	go func() {
		runErr = Run(ctx, cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
		close(finished)
	}()
	defer func() {
		cancel()
		select {
		case <-finished:
			if runErr != nil {
				t.Errorf("daemon failed: %v", runErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("daemon did not stop its local workers")
		}
	}()
	client := &http.Client{Timeout: 500 * time.Millisecond, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	retry := time.NewTicker(10 * time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case <-finished:
			t.Fatalf("shared-password startup failed: %v", runErr)
		case <-deadline.C:
			t.Fatal("shared-password daemon did not become live")
		case <-retry.C:
			response, err := client.Get("http://" + cfg.ControlAddress + "/status")
			if err != nil {
				continue
			}
			var status struct {
				Cameras []struct {
					Enabled    bool
					Management *struct{}
					Media      struct{ Listening bool }
				}
			}
			err = json.NewDecoder(response.Body).Decode(&status)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK || err != nil || len(status.Cameras) != 1 || !status.Cameras[0].Enabled || status.Cameras[0].Management == nil || !status.Cameras[0].Media.Listening {
				t.Fatal("shared-password camera listeners did not start")
			}
			return
		}
	}
}

func reserveLoopbackAddresses(t *testing.T, count int) []string {
	t.Helper()
	var addresses []string
	for range count {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		addresses = append(addresses, listener.Addr().String())
	}
	return addresses
}

func writeLoopbackTLSIdentity(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificatePath, keyPath := filepath.Join(directory, "camera.crt"), filepath.Join(directory, "camera.key")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}), 0600); err != nil {
		t.Fatal(err)
	}
	return certificatePath, keyPath
}
