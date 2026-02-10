// pkg/engine/asset.go
package engine

import (
	"time"
)

// ProbeObservation captures the result of an active probe execution.
// This struct is used in banner grabbing to record individual probe attempts
// and their responses, including TLS metadata when applicable.
type ProbeObservation struct {
	ProbeID     string          `json:"probe_id" yaml:"probe_id"`
	Description string          `json:"description,omitempty" yaml:"description,omitempty"`
	Protocol    string          `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	IsTLS       bool            `json:"is_tls,omitempty" yaml:"is_tls,omitempty"`
	Duration    time.Duration   `json:"duration_ns,omitempty" yaml:"duration_ns,omitempty"`
	Response    string          `json:"response,omitempty" yaml:"response,omitempty"`
	Error       string          `json:"error,omitempty" yaml:"error,omitempty"`
	TLS         *TLSObservation `json:"tls,omitempty" yaml:"tls,omitempty"` // Phase 1.7
}

// TLSObservation captures TLS handshake metadata including certificate validity.
// Phase 1.7: Added certificate expiry and self-signed detection for security assessment.
type TLSObservation struct {
	Version        string    `json:"version,omitempty" yaml:"version,omitempty"`
	CipherSuite    string    `json:"cipher_suite,omitempty" yaml:"cipher_suite,omitempty"`
	ServerName     string    `json:"server_name,omitempty" yaml:"server_name,omitempty"`
	PeerCommonName string    `json:"peer_common_name,omitempty" yaml:"peer_common_name,omitempty"`
	PeerDNSNames   []string  `json:"peer_dns_names,omitempty" yaml:"peer_dns_names,omitempty"`
	Issuer         string    `json:"issuer,omitempty" yaml:"issuer,omitempty"`        // Phase 1.7: Certificate issuer DN
	NotBefore      time.Time `json:"not_before,omitzero" yaml:"not_before,omitempty"` // Phase 1.7: Certificate validity start
	NotAfter       time.Time `json:"not_after,omitzero" yaml:"not_after,omitempty"`   // Phase 1.7: Certificate validity end
	IsExpired      bool      `json:"is_expired" yaml:"is_expired"`                    // Phase 1.7: True if cert expired
	IsSelfSigned   bool      `json:"is_self_signed" yaml:"is_self_signed"`            // Phase 1.7: True if Subject == Issuer
}

// FindingSeverity defines the severity of a finding.
type FindingSeverity string

const (
	SeverityCritical     FindingSeverity = "critical"
	SeverityHigh         FindingSeverity = "high"
	SeverityMedium       FindingSeverity = "medium"
	SeverityLow          FindingSeverity = "low"
	SeverityInfo         FindingSeverity = "informational"
	SeverityUndetermined FindingSeverity = "undetermined"
)

// VulnerabilityFinding details a specific vulnerability found.
type VulnerabilityFinding struct {
	ID           string          `json:"id" yaml:"id"`                       // CVE ID, Vulntor Vuln ID, etc.
	SourceModule string          `json:"source_module" yaml:"source_module"` // Which module instance found this
	Summary      string          `json:"summary" yaml:"summary"`
	Severity     FindingSeverity `json:"severity" yaml:"severity"`
	Description  string          `json:"description,omitempty" yaml:"description,omitempty"`
	References   []string        `json:"references,omitempty" yaml:"references,omitempty"`
	Remediation  string          `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	// Evidence string `json:"evidence,omitempty" yaml:"evidence,omitempty"` // Specific evidence
}

// ServiceDetails contains information about the service running on a port.
type ServiceDetails struct {
	Name             string             `json:"name,omitempty" yaml:"name,omitempty"`             // e.g., SSH, HTTP
	Product          string             `json:"product,omitempty" yaml:"product,omitempty"`       // e.g., OpenSSH, Nginx (parser'dan gelen daha spesifik ürün adı)
	Version          string             `json:"version,omitempty" yaml:"version,omitempty"`       // e.g., 8.2p1, 1.22.1
	TechTags         []string           `json:"tech_tags,omitempty" yaml:"tech_tags,omitempty"`   // e.g., [apache, httpd, mod_ssl]
	RawBanner        string             `json:"raw_banner,omitempty" yaml:"raw_banner,omitempty"` // Raw banner captured
	IsTLS            bool               `json:"is_tls,omitempty" yaml:"is_tls,omitempty"`
	ParsedAttributes map[string]any     `json:"parsed_attributes,omitempty" yaml:"parsed_attributes,omitempty"` // HTTP headers, SSH specific details, etc.
	Evidence         []ProbeObservation `json:"evidence,omitempty" yaml:"evidence,omitempty"`                   // Active probe results from Phase 1.5 (Probe Fallback)
}

// PortProfile details information about a specific open port on a target.
type PortProfile struct {
	PortNumber      int                    `json:"port_number" yaml:"port_number"`
	Protocol        string                 `json:"protocol" yaml:"protocol"` // "tcp", "udp"
	Status          string                 `json:"status" yaml:"status"`     // "open", "filtered", "closed"
	Service         ServiceDetails         `json:"service,omitzero" yaml:"service,omitempty"`
	Vulnerabilities []VulnerabilityFinding `json:"vulnerabilities,omitempty" yaml:"vulnerabilities,omitempty"`
}

// AssetProfile represents a comprehensive profile for a single scanned target.
type AssetProfile struct {
	Target               string                   `json:"target" yaml:"target"`                                 // Original target string (IP, hostname, CIDR)
	ResolvedIPs          map[string]time.Time     `json:"resolved_ips,omitempty" yaml:"resolved_ips,omitempty"` // Map of IP to first_seen_alive_time
	Hostnames            []string                 `json:"hostnames,omitempty" yaml:"hostnames,omitempty"`
	IsAlive              bool                     `json:"is_alive" yaml:"is_alive"` // If any IP resolved from target is alive
	FirstSeenAlive       time.Time                `json:"first_seen_alive,omitzero" yaml:"first_seen_alive,omitempty"`
	LastObservationTime  time.Time                `json:"last_observation_time" yaml:"last_observation_time"`           // When data for this asset was last updated
	OpenPorts            map[string][]PortProfile `json:"open_ports_by_ip,omitempty" yaml:"open_ports_by_ip,omitempty"` // Keyed by IP address
	TotalVulnerabilities int                      `json:"total_vulnerabilities" yaml:"total_vulnerabilities"`
	// OperatingSystem string `json:"operating_system,omitempty" yaml:"operating_system,omitempty"`
	// MACAddress string `json:"mac_address,omitempty" yaml:"mac_address,omitempty"`
	ErrorsEncountered []string `json:"errors_encountered,omitempty" yaml:"errors_encountered,omitempty"` // Errors specific to this asset during scan
}
