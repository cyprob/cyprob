# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
