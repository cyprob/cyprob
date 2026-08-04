# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- TCP port discovery under-reported open ports from the CLI. The module's
  `ConfigSchema` defaults contradicted its Go defaults, and the planner seeds
  module config from the schema, so scans silently ran with
  `stop_on_first_open` enabled and `verification_pass_enabled` disabled — the
  opposite of the intended behavior. A scan therefore stopped at the first open
  port instead of scanning the requested range. On a real printer this reported
  3 open ports where 5 were open, missing 443 and 631. The schema now derives
  from the same defaults as the Go config, so there is a single source of truth.
- `stop_on_first_open` probed strictly sequentially, so every filtered port ahead
  of the first open one cost a full timeout in series; a host answering only on a
  high port could take over an hour. Ports are now probed in small concurrent
  batches, keeping the low probe count the option exists for while removing the
  pathological case. The reported port is whichever answers first within its
  batch, not necessarily the lowest.

### Changed
- The two-phase sweep is now on by default (500ms), matching the Enterprise
  default so both editions exercise one behavior; `sweep_timeout: 0` restores
  the classic single pass. An explicit zero is now honored — it was previously
  treated as "unset" and silently ignored, so the documented opt-out did not
  work. The sweep and the verification pass now move together: disabling
  verification also disables the sweep, since a shortened first pass with no
  re-probe would be strictly worse than a single pass.

### Added
- HTTP favicon fingerprinting for device identification. A new `favicon-probe`
  fetches `/favicon.ico` from HTTP and HTTPS services (including the common
  management ports) and emits a favicon hash, which is a stable device
  fingerprint: the same hardware and firmware serve the same icon, so identical
  devices group together across a fleet even before anyone names them.
  The hash follows the de-facto Shodan convention - MurmurHash3 x86 32-bit over
  the MIME-style base64 encoding - so publicly published favicon hashes are
  directly usable as corpus candidates. The implementation is verified against
  canonical reference vectors, because a drift would silently invalidate every
  corpus entry.
  The identity corpus ships empty on purpose: an entry asserts "this hash IS this
  product", so a wrong one mislabels every matching device in every scan.
  Unrecognized hashes are still emitted and remain useful for grouping; entries
  are added only after verification against a real device.
- `tools/seed_favicon.go` grows the favicon corpus from real devices: it fetches
  the icon, computes the hash, and surfaces what the device says about itself
  (device-info endpoints, UPnP description) so an entry can be confirmed from the
  device's own statement rather than inference.

## [0.15.0] - 2026-08-03

### Added
- Operating system identification from the SSH banner. Linux distributions patch
  OpenSSH and name themselves in the banner comment
  ("OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"), which the probe previously discarded.
  SSH is reachable on virtually every Linux server, so this is a credential-free
  OS signal across the bulk of an estate - and an OS version feeds version-based
  CVE correlation, not just the inventory.
  Debian/Raspbian releases are read directly from the package suffix ("+deb11u3"
  -> 11), which the banner states. Ubuntu is inferred from the OpenSSH version it
  freezes per release, limited to LTS releases; an unmapped version yields no
  version rather than a guess. Banners that name no distribution (stock OpenSSH,
  most appliances) assert nothing.
- Device identification from TLS certificates. Appliances and management
  interfaces sign their own certificates and name themselves in the subject or
  issuer ("CN=FortiGate", "O=Ubiquiti Inc.", "CN=iDRAC default certificate"),
  which identifies hosts that expose no SNMP, no banner and no recognizable web
  UI. The certificate fields were already collected but were only stored as raw
  attributes; they now yield a vendor and product into the canonical service
  identity and the asset-level device profile.
  Matching is a curated allowlist, not a heuristic: a certificate CN is usually
  just a hostname, so nothing is asserted unless a known product marker matches,
  and markers must occur at a word start (a plain substring match labels
  "pilot.example.com" an HPE iLO).

## [0.14.0] - 2026-08-03

### Added
- MAC vendor identification via the IEEE OUI registry. Assets on a directly
  attached segment now carry their link-layer address and a manufacturer, which
  is often the only vendor signal a device gives: hardware that exposes no SNMP,
  no banner and no management UI still has a manufacturer-assigned MAC. The
  table is generated from the authoritative IEEE registry (`gen_oui.go`), never
  hand-maintained, and is decompressed lazily on first lookup.
  Locally-administered (randomized privacy) and multicast addresses are
  deliberately not resolved, since their leading bytes are not an OUI.
- Asset-level device identity now merges multiple sources strongest-first: SNMP
  states the device outright, mDNS reports what it advertises about itself, and
  the MAC OUI names a manufacturer when nothing else does. The profile's
  `source` records every signal that actually contributed.
- Native mDNS (DNS-SD) probe on UDP/5353. Hosts that answer Bonjour publish an
  exact hardware model and OS version, so this yields device identity for hosts
  that expose nothing else identifiable - and the version feeds CVE correlation.
  Queries are unicast and bounded (one service enumeration plus a few
  identity-bearing service types), and derive vendor/model/version/device-type
  from DNS-SD TXT conventions (`model`, `md`, `usb_MFG`/`usb_MDL`, `osvers`).
  Device class comes from the advertised service types (printer, media device,
  storage, IoT) with the Apple hardware-identifier families as a fallback.
  Results flow into the canonical service identity, including the hostname hint.

### Changed
- UDP port discovery now probes 5353 (mDNS) by default and sends a DNS-SD
  service-enumeration payload for it, so mDNS-speaking devices are actually
  discovered rather than missed.

## [0.13.0] - 2026-07-22

### Added
- Two-phase TCP port discovery via a new `sweep_timeout` option. When set, the
  first pass sweeps all requested ports at this short timeout (open/refused
  ports resolve fast; only filtered ports pay the short wait), then a
  verification pass re-checks only the timed-out ports at the full `timeout` to
  recover slow-responding open ports. Refused ports (definitively closed) are no
  longer re-probed. This makes full-range (1-65535) scans practical without a
  stateless SYN scanner. `sweep_timeout: 0` keeps the classic single pass.

## [0.12.0] - 2026-07-22

### Added
- Asset-level device identity. `AssetProfile` now carries a `Device` profile
  (vendor, product, model, serial, type/role) synthesized from probe evidence,
  so an asset is identified as a device ("Fortinet FortiGate-100F firewall")
  rather than only as a bag of per-port services. Populated from the SNMP probe;
  the field is the place where make/model/role identification now lands.
- SNMP chassis model and serial number via ENTITY-MIB. For SNMP devices that
  expose ENTITY-MIB, the probe now walks `entPhysicalModelName` /
  `entPhysicalSerialNum` (preferring the chassis entry) and reports the exact
  `model` and `serial`. Best-effort and bounded: only attempted for identified
  devices, bails early when the device has no ENTITY-MIB, and never fails the
  probe. Credential-free.
- SNMP device type/role classification. The native SNMP probe now emits a coarse
  `device_type` (firewall, load-balancer, wireless-ap, printer, ups, storage,
  hypervisor, switch, router, server) inferred from the system description and
  the PEN-derived vendor. Credential-free; only commits a role when a signal is
  clear (multi-category vendors like Cisco/Juniper are classified from the
  description, not the vendor, to avoid wrong labels).
- SNMP device-vendor identification via IANA Private Enterprise Numbers. The
  native SNMP probe now maps a device's `sysObjectID` enterprise number to a
  manufacturer (Fortinet, Palo Alto, F5, Juniper, HP, Aruba, printers, UPS,
  storage, ...) instead of recognizing only four hardcoded vendors. Works on
  unauthenticated v1/v2c/v3 responses; expands device make coverage for asset
  inventory. Specific descr-based patterns (Cisco IOS, Windows, MikroTik,
  Net-SNMP) still take precedence and continue to extract versions.
- SNMPv3 (USM) support in the native SNMP probe. When an SNMPv3 username is
  configured, a v3 attempt is tried before the v1/v2c community fallbacks
  (hardened targets such as banks disable v1/v2c and mandate v3). Auth protocols
  MD5/SHA/SHA224/SHA256/SHA384/SHA512 and privacy DES/AES/AES192/AES256 are
  supported; the security level (authPriv / authNoPriv / noAuthNoPriv) is derived
  from the supplied passphrases. Probe output records the security name and
  security level for v3 exchanges.

## [0.11.0] - 2026-07-06

### Added
- Apache Tomcat version detection via HTTP identity hints: Tomcat sends no
  Server header, so the version is extracted from the default error-page/footer
  marker `Apache Tomcat/<version>` in the response body/title, yielding
  product `Apache Tomcat` + version for CVE correlation. HTTP identity hints
  now also evaluate common HTTP-alt ports (8000/8080/8081).

## [0.10.0] - 2026-07-06

### Added
- Native Redis probe (port 6379): unauthenticated `INFO` parsing for
  `redis_version`, mode, os, arch; identifies auth-required Redis without a
  version. Feeds canonical service identity (product/vendor/version + tech
  tag `redis`).
- Native PostgreSQL probe (port 5432): v3 startup handshake that extracts
  `server_version` from ParameterStatus when the server leaks it (trust /
  pre-auth), and identifies auth-required PostgreSQL otherwise. Feeds
  canonical service identity (product/vendor/version + tech tag
  `postgresql`).

## [0.9.0] - 2026-06-11

### Added
- cPanel-family service identity coverage in HTTP identity parsing: cPanel, WHM, and cPanel Webmail are recognized as separate services via login/session markers (`cprelogin`, `whostmgrrelogin`, `webmailrelogin`) and port-aware redirect matchers (`2082/2083 -> cpanel`, `2086/2087 -> whm`, `2095/2096 -> cpanel_webmail`), including slashless `Location` redirects.
- Exact cPanel-family tech tags: `cpanel`, `whm`, `cpanel_webmail`.
- Tests covering cPanel-family identity hints, normalization, and tech tagging.

### Changed
- Control WebPanel (CWP) responses (`cwpsrv`, `cwp_theme`) are excluded from cPanel redirect rules to prevent false positives.

### Removed
- `hosting_panel` generated tech tag; consumers must select on exact cPanel-family tags.

## [0.8.0] - 2026-05-05

### Added
- TCP port discovery results now report timed out, refused, and other failed ports alongside open ports.
- Targeted tests covering timeout classification, refusal classification, and verification-pass recovery behavior.

### Changed
- TCP port discovery now supports per-port timeout overrides and an optional verification pass for missed ports.

## [0.7.0] - 2026-04-28

### Added
- Native Telnet probe coverage with structured banner, negotiation, vendor, product, and version metadata.
- `scan-debug` visibility for Telnet native probe outputs.
- Telnet-aware service identity normalization, tech tagging, and asset profile enrichment.

### Changed
- TCP port discovery now supports configurable per-port retries for transient connection failures.

## [0.6.0] - 2026-03-16

### Added
- Native protocol-aware probes for `ssh`, `smtp`, `ftp`, `mysql`, `snmp`, `dns`, `winrm`, `smb`, `rdp`, `rpc`, and `tls`.
- Canonical service identity normalization and richer asset profile enrichment for native probe outputs.
- Extended `scan-debug` coverage for native probe stages, UDP discovery visibility, and protocol-specific debug payloads.
- New fingerprint coverage for SmarterMail and CrushFTP service banners.
- Deep RDP metadata enrichment for TLS certificate details, NTLM target info, and security capability flags.

### Fixed
- Prevented empty scan results when ICMP host discovery returns no live hosts but port discovery succeeds.
- Decoupled TCP and UDP port scans from ICMP host discovery requirements.
- Improved HTTP/HTTPS banner capture with proxy-aware origin retry and same-host redirect following.
- Preserved stronger native SSH detail precedence during reporting and canonical identity generation.

### Changed
- Simplified canonical service pipeline wiring and centralized service identity normalization.
- Shared native probe module wiring across scan stages.
- DNS detection now uses protocol-aware native probing instead of relying only on banner and fingerprint heuristics.

## [0.5.3] - 2026-03-06

### Added
- SMTP fingerprint coverage for Sophos ESMTP banners.
- Rule-based resolver tests for Sophos SMTP positive and near-miss negative cases.
- Validation dataset entries for Sophos SMTP true-positive/true-negative scenarios.

## [0.5.1] - 2026-02-17

### Fixed
- **TCP discovery fallback cost reduction**
  - Added `stop_on_first_open` behavior to `tcp-port-discovery` for discovery-oriented usage.
  - When enabled, per-target scanning now stops after the first open TCP port is found.
  - Preserved full-scan behavior when the flag is disabled (default remains unchanged).
- Added targeted tests to verify:
  - Early-exit only affects the current target.
  - Other targets continue scanning.
  - Full scan behavior remains intact when early-exit is disabled.

## [0.5.0] - 2026-02-16

### Added
- Internal debug CLI command: `scan-debug target <host-or-ip>`
  - Step-by-step visibility for resolve -> port discovery -> banner -> fingerprint -> tech tags.
  - JSON/pretty output with step-level errors and warnings.
- Domain-to-IP context propagation for probes
  - Preserves original hostname after DNS resolution.
  - Applies `Host` and TLS SNI correctly for domain targets.
- Canonical mail-focused tech tagging baseline
  - Added canonical tag source-of-truth and normalization/alias handling.
  - Added Phase-1 mail stack rules (`mail_service`, `smtp`, `imap`, `pop3`, `webmail`, vendor/product mail tags).
  - Added guard tests to fail on non-canonical tag emission.

### Fixed
- Reduced WinRM false positives in fingerprint attribution for HTTP 400-style responses.
- Normalized `https-get` request crafting to canonical HTTP/1.1 request format, reducing false `400 Bad Request` responses.
- Corrected `source_probe` attribution visibility in scan-debug evidence flow.

### Changed
- Go module path migrated to `github.com/cyprob/cyprob`.
- Added roadmap document for tech-tagger Phase 2/3 planning: `_docs/tech-tagger-roadmap.md`.

## [0.4.0] - 2026-02-10

### Added
- **New Module: Tech-Tagger** ([e01d620](e01d620))
  - Implemented regex-based technology detection engine with custom rule support.
  - Added automatic mapping of high-confidence fingerprints to technology tags (e.g., Apache -> apache, http_server).
  - Integrated `tech_tags` field into JSON reports for richer service context.
  - Supports dynamic rule loading via embedded YAML configuration.
- **Service Enrichment**
  - Updated `ServiceDetails` struct to include `TechTags` field.
  - Enhanced `AssetProfileBuilder` to consume and aggregate tech tags from the new module.


## [0.3.0] - 2026-01-06

### Added
- **Streaming event architecture for real-time scan result reporting** ([3024975](3024975))
  - StreamEvent interface with 5 event types: TargetStarted, TargetCompleted, PortOpen, ServiceDetected, VulnFound
  - StreamPublisher with subscribe/publish pattern for event-driven architecture
  - Context-based injection system for optional streaming capabilities
  - Comprehensive test coverage with 16 test cases
- **Per-target parallelization in TCP port discovery** ([3024975](3024975))
  - Removed batch wait bottleneck (32 IPs waiting together)
  - Each IP scans independently and emits completion events
  - Real-time progress tracking with 30-second feedback loops
  - 3600% improvement in first-result latency (18 minutes → 30 seconds)

### Performance
- TCP port discovery now processes targets in parallel without batch blocking
- First IP results no longer wait for slowest IP in chunk
- Maintains backward compatibility - streaming is optional via context injection

## [0.2.0] - 2026-01-04

### Added
- HTTP security headers analysis with scoring and recommendations ([74737a2](74737a2))
  - Parse HSTS, CSP, X-Frame-Options, X-Content-Type-Options headers
  - Calculate security score (0-100) based on header presence
  - Generate recommendations for missing security headers
- `--targets` flag for flexible target specification ([95e1adf](95e1adf))
  - Support multiple formats: `-t IP1,IP2` or `-t IP1 -t IP2`
  - Merge flag targets with positional arguments
  - Maintain backward compatibility
- UDP port discovery module ([d4a2fd1](d4a2fd1))
  - Protocol-specific payloads for DNS, SNMP, NTP, Syslog, UPnP
  - ICMP unreachable detection for filtered ports
  - Auto-registration with module factory
- ConfigSource interface for extensible configuration ([2ef2465](2ef2465))
  - Support for environment variables with `VULNTOR_*` prefix
  - Pluggable source system with priority ordering
  - Built-in sources: Default, File, Env, Flag
- XDG Base Directory Specification support for plugin cache ([aed8286](aed8286))

### Fixed
- Configuration file loading now errors when explicit `--config` file not found ([7113519](7113519))
  - Silent skip only for default/empty paths
  - Required field added to FileSource

### Removed
- **SECURITY**: Removed `dev_mode` authentication bypass backdoor ([f0a65ef](f0a65ef))
- Unused `BindServerFlags` function and related tests ([f0a65ef](f0a65ef))
- `config` command from root CLI ([320aa71](320aa71))

### Changed
- Refactored configuration loading to use source-based architecture ([2ef2465](2ef2465))

## [0.1.0-rc.2] - Previous Release

Initial release candidate with core scanning capabilities.

[Unreleased]: https://github.com/cyprob/cyprob/compare/v0.12.0...HEAD
[0.12.0]: https://github.com/cyprob/cyprob/compare/v0.11.0...v0.12.0
[0.8.0]: https://github.com/cyprob/cyprob/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/cyprob/cyprob/compare/v0.6.1...v0.7.0
[0.6.0]: https://github.com/cyprob/cyprob/compare/v0.5.3...v0.6.0
[0.5.3]: https://github.com/cyprob/cyprob/compare/v0.5.2...v0.5.3
[0.5.1]: https://github.com/cyprob/cyprob/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/cyprob/cyprob/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/cyprob/cyprob/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/cyprob/cyprob/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/cyprob/cyprob/compare/v0.1.0-rc.2...v0.2.0
[0.1.0-rc.2]: https://github.com/cyprob/cyprob/releases/tag/v0.1.0-rc.2
