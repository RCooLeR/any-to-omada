# Development

Use Go **1.27.3**, as declared in [go.mod](../go.mod). Routing tests need Python 3.12+ and a POSIX shell on Linux or WSL; CI uses Python 3.15. The [CI workflow](../.github/workflows/ci.yml) runs the Go checks and local routing tests without physical devices.

## Verify changes

Run from the repository root:

```sh
go mod verify
gofmt -l cmd internal
go vet ./...
go test -race ./...
go run ./cmd/any-to-omada check --config config.example.json
go build -o ../any-to-omada-bin ./cmd/any-to-omada
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s deploy/mango/tests -p 'test_*.py'
sh -n deploy/mango/camera-aliases.sh
sh -n deploy/mango/camera-forwarding.sh
sh -n deploy/mango/camera-routed-forwarding.sh
```

`gofmt -l` should produce no output. The example configuration is disabled, so `check` does not resolve secrets or contact cameras.

Mango tests use fake commands and disposable files; they do not configure a router. Their default fixture directory is `$HOME/.cache/any-to-omada-tests`. Set `MANGO_TEST_WORK` to override it. Use native Linux/WSL storage and avoid paths under `/tmp`, `/etc`, `/var/lock` or `/overlay`, which the test fixture rewrites.

Passing software tests does not establish live enrollment, recorder-history acceptance or physical actuation. Those need separate device evidence. Preserve that distinction in documentation and status fields; the [protocol reference](omada-protocol.md) records observed behavior and open questions.

## Components

| Path | Responsibility |
| --- | --- |
| [cmd/any-to-omada](../cmd/any-to-omada) | `serve`, `check`, `healthcheck` and `version` commands. |
| [internal/config](../internal/config) | Strict inventory, credential references and per-lens validation. |
| [internal/app](../internal/app) | Shared physical-source subscriptions, virtual-camera lifecycle, callbacks and loopback API. |
| [internal/dvripcapture](../internal/dvripcapture), [internal/isapievents](../internal/isapievents), [internal/onvifevents](../internal/onvifevents) | Source event adapters. |
| [internal/cameraevents](../internal/cameraevents) | Event normalization and explicit classification mappings. |
| [internal/camerartsp](../internal/camerartsp), [internal/tpmarker](../internal/tpmarker) | Shared upstream RTSP streams, authenticated output and optional in-video markers. |
| [internal/omadafront](../internal/omadafront) | HTTPS management and virtual camera settings. |
| [internal/omadalink](../internal/omadalink), [internal/spakeee](../internal/spakeee) | Native callback transport, authentication and passthrough. |
| [internal/eventstore](../internal/eventstore) | Bounded segmented JSONL journal. |
| [internal/onvifptz](../internal/onvifptz), [internal/onvifoutput](../internal/onvifoutput) | Opt-in physical PTZ and advertised relay controls. |
| [deploy/mango](../deploy/mango) | Reference routing profiles and local transaction tests. |

Raw captures, private runtime configuration, credentials, binaries and research-only proxies are not distributed in the repository. Keep third-party and cryptographic attributions when redistributing code; see [legal notices](legal.md), [LICENSE](../LICENSE), [NOTICE](../NOTICE) and [THIRD_PARTY_NOTICES](../THIRD_PARTY_NOTICES).

[Documentation index](../README.md)
