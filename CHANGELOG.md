# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/vulntor/vulntor/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/vulntor/vulntor/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/vulntor/vulntor/compare/v0.1.0-rc.2...v0.2.0
[0.1.0-rc.2]: https://github.com/vulntor/vulntor/releases/tag/v0.1.0-rc.2
