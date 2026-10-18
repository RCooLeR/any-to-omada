# License and project notice

Any to Omada is an unofficial DIY interoperability project. Original project
code and documentation are available under the [MIT License](../LICENSE).
See [NOTICE](../NOTICE) for trademark and affiliation information.

## Temporary compatibility layer

The project is intended as a temporary workaround for installations where
native camera-to-recorder integration, including ONVIF, does not carry the
streams, events, or controls the operator needs. It translates supported
camera interfaces into the observed Omada camera protocol.

The goal is to make this layer unnecessary when native interoperability covers
the installation's requirements. This is the project's direction, not a claim
that TP-Link or another vendor has promised an ONVIF change, a firmware fix, or
a delivery date.

Compatibility depends on the camera model, firmware, recorder, protocol, and
configuration. A supported protocol or brand name does not establish support
for every device or event type. The [getting started guide](getting-started.md)
documents supported features and evidence; the [events](events.md) and
[physical controls](controls.md) guides explain their limits. The project is not an availability
guarantee or a substitute for vendor-supported recording and alarm systems.

## Independent project

This project is not affiliated with, endorsed by, or sponsored by TP-Link,
Omada, ONVIF, or any camera or recorder vendor. Product names are used to
identify interoperability targets. Neither the project name nor its protocol
implementations imply vendor approval, access to vendor support, or ONVIF
certification.

Use the service with equipment and accounts you own or are authorized to
operate. The software license covers this project's code; it does not grant
rights to third-party firmware, trademarks, services, or device accounts.

## Third-party notices

Third-party code and dependencies keep their original licenses. The project's
MIT license does not replace those terms.

- [Third-party notices](../THIRD_PARTY_NOTICES) collect the upstream license
  texts and additional source attributions for the runtime Go dependencies and
  Go runtime/standard library. The inventory covers static Linux amd64/arm64
  and Windows amd64 builds with Go 1.27.2; recheck it when dependencies, build
  targets, or the toolchain change.
- [SPAKE2+ interoperability notices](../internal/spakeee/NOTICE) retain the
  attribution and BSD 2-Clause terms for Frank Denis's `spake2-ee` work, and
  the attribution and ISC terms for the libsodium Elligator2 mapping.
- [Cryptographic dependency notices](../internal/spakeee/DEPENDENCY_NOTICES)
  retain the license texts for `filippo.io/edwards25519`,
  `golang.org/x/crypto`, and `github.com/dchest/blake2b`.
- Go dependencies are identified and versioned in [go.mod](../go.mod)
  and [go.sum](../go.sum); their upstream license terms apply to those
  components. The cryptographic notices supplement the full runtime inventory
  in `THIRD_PARTY_NOTICES`.

Redistribution must retain the applicable copyright and license notices,
including those required by dependencies included in a distributed binary or
container image.

## Warranty

The software is provided "AS IS", without warranty, under the terms in
[LICENSE](../LICENSE). Experimental compatibility behavior may change between
versions; validate the functions your installation relies on before using a
new release in production.
