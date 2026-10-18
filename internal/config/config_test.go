package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func valid() Config {
	account := Account{Username: "viewer", PasswordEnv: "SOURCE_PASSWORD"}
	return Config{ControlAddress: "127.0.0.1:19031", Storage: Storage{Directory: "data", SegmentBytes: 4 << 20, Segments: 4}, Sources: []Source{{ID: "dual", Enabled: true, Brand: "imou", Host: "192.0.2.10", NativePort: 37777, Account: account}}, Cameras: []Camera{{ID: "ptz", Enabled: true, Verified: true, SourceID: "dual", SourceIndex: 0, Lens: "ptz", AdvertisedIP: "192.0.2.30", RecorderIP: "192.0.2.150", ManagementAddress: "0.0.0.0:18443", RTSPAddress: "0.0.0.0:18554", AllowedTransportPeers: []string{"192.0.2.2"}, MainURL: "rtsp://192.0.2.10:554/cam/realmonitor?channel=1&subtype=0", SubURL: "rtsp://192.0.2.10:554/cam/realmonitor?channel=1&subtype=1", Account: Account{Username: "proxy", PasswordEnv: "PROXY_PASSWORD"}, TLSCertificateFile: "cert.pem", TLSKeyFile: "key.pem"}}}
}

func TestValidationRejectsAmbiguousRoutingAndInvalidPeers(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"unverified enabled lens":   func(c *Config) { c.Cameras[0].Verified = false },
		"source disabled":           func(c *Config) { c.Sources[0].Enabled = false },
		"foreign source URL":        func(c *Config) { c.Cameras[0].MainURL = "rtsp://192.0.2.99:554/main" },
		"URL credentials":           func(c *Config) { c.Cameras[0].MainURL = "rtsp://user:password@192.0.2.10:554/main" },
		"peer subnet":               func(c *Config) { c.Cameras[0].AllowedTransportPeers = []string{"192.0.2.0/24"} },
		"duplicate peers":           func(c *Config) { c.Cameras[0].AllowedTransportPeers = []string{"192.0.2.2", "192.0.2.2"} },
		"listener conflict":         func(c *Config) { c.Cameras[0].RTSPAddress = "127.0.0.1:19031" },
		"wildcard conflict":         func(c *Config) { c.Cameras[0].RTSPAddress = "0.0.0.0:19031" },
		"broadcast VIP":             func(c *Config) { c.Cameras[0].AdvertisedIP = "255.255.255.255" },
		"duplicate physical source": func(c *Config) { c.Sources = append(c.Sources, c.Sources[0]) },
		"duplicate lens": func(c *Config) {
			v := c.Cameras[0]
			v.ID = "duplicate"
			v.AdvertisedIP = "192.0.2.31"
			v.ManagementAddress = "0.0.0.0:18444"
			v.RTSPAddress = "0.0.0.0:18555"
			c.Cameras = append(c.Cameras, v)
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid()
			mutate(&cfg)
			if cfg.Validate() == nil {
				t.Fatal("unsafe or ambiguous configuration accepted")
			}
		})
	}
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAllowsMissingOrEmptyTransportPeers(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		cfg := valid()
		cfg.Cameras[0].AllowedTransportPeers = nil
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if explicit {
			var fields map[string]any
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			fields["cameras"].([]any)[0].(map[string]any)["allowed_transport_peers"] = []string{}
			data, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
		}
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		loaded, err := Load(path)
		if err != nil || len(loaded.Cameras[0].AllowedTransportPeers) != 0 {
			t.Fatalf("unrestricted camera configuration failed: explicit=%t error=%v", explicit, err)
		}
	}
}

func TestDisabledUnverifiedLensNeedsNoStreamURLOrResolvedSecrets(t *testing.T) {
	cfg := valid()
	cfg.Cameras[0].Enabled = false
	cfg.Cameras[0].Verified = false
	cfg.Cameras[0].MainURL = ""
	cfg.Cameras[0].SubURL = ""
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestChannelLensPreservesMappingVerification(t *testing.T) {
	for _, test := range []struct {
		name     string
		lens     string
		verified bool
		enabled  bool
		valid    bool
	}{
		{"verified channel", "channel", true, true, true},
		{"unverified channel mapping", "channel", false, true, false},
		{"enabled unverified label", "unverified", true, true, false},
		{"disabled unverified lens", "unverified", false, false, true},
		{"existing fixed lens", "fixed", true, true, true},
		{"unknown label", "other", true, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid()
			cfg.Cameras[0].Lens = test.lens
			cfg.Cameras[0].Verified = test.verified
			cfg.Cameras[0].Enabled = test.enabled
			if err := cfg.Validate(); (err == nil) != test.valid {
				t.Fatalf("mapping validation: got error %v, want valid %t", err, test.valid)
			}
		})
	}
}

func TestAccountReadsOnlyBoundedSecretReference(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("test-secret\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := (Account{Username: "viewer", PasswordFile: path}).Resolve()
	if err != nil || got != "test-secret" {
		t.Fatal("file reference did not resolve")
	}
	if err := os.WriteFile(path, make([]byte, 4097), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Account{Username: "viewer", PasswordFile: path}).Resolve(); err == nil {
		t.Fatal("oversized secret accepted")
	}
}
