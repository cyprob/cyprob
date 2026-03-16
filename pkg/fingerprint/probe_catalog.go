package fingerprint

import (
	"fmt"
	"slices"
	"strings"
)

// ProbeCatalog represents the set of active probe groups that the scanner can execute.
// Groups can map to protocol families (HTTP, SMTP, etc.) and expose one or more probe
// definitions that should be attempted when their match conditions are satisfied.
// FallbackProbeIDs lists probe IDs to try when no port-specific probes match (Phase 1.5).
type ProbeCatalog struct {
	Groups           []ProbeGroup `yaml:"groups" json:"groups"`
	FallbackProbeIDs []string     `yaml:"fallback_probes,omitempty" json:"fallback_probes,omitempty"`
}

// ProbeGroup describes a family of probes sharing similar trigger conditions.
type ProbeGroup struct {
	ID             string      `yaml:"id" json:"id"`
	Description    string      `yaml:"description,omitempty" json:"description,omitempty"`
	PortHints      []int       `yaml:"port_hints,omitempty" json:"port_hints,omitempty"`
	ProtocolHints  []string    `yaml:"protocol_hints,omitempty" json:"protocol_hints,omitempty"`
	Probes         []ProbeSpec `yaml:"probes" json:"probes"`
	AdditionalTags []string    `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// ProbeSpec describes a single active probe that banner_grab can execute.
// The payload is a raw string that will be written as-is to the remote endpoint.
type ProbeSpec struct {
	ID              string            `yaml:"id" json:"id"`
	Description     string            `yaml:"description,omitempty" json:"description,omitempty"`
	Protocol        string            `yaml:"protocol" json:"protocol"`
	UseTLS          bool              `yaml:"use_tls,omitempty" json:"use_tls,omitempty"`
	Payload         string            `yaml:"payload" json:"payload"`
	Headers         map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Timeout         string            `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	PortInclude     []int             `yaml:"port_include,omitempty" json:"port_include,omitempty"`
	PortExclude     []int             `yaml:"port_exclude,omitempty" json:"port_exclude,omitempty"`
	SkipInitialRead bool              `yaml:"skip_initial_read,omitempty" json:"skip_initial_read,omitempty"`
}

// ProbesFor filters catalog probes for the given port and optional protocol hints.
// It returns every probe whose group matches the port/hints and whose own include/exclude
// clauses allow the port.
func (c *ProbeCatalog) ProbesFor(port int, hints []string) []ProbeSpec {
	if c == nil {
		return nil
	}

	normalizedHints := normalizeHints(hints)
	out := make([]ProbeSpec, 0)

	for _, group := range c.Groups {
		if !group.matches(port, normalizedHints) {
			continue
		}

		for _, probe := range group.Probes {
			if !probe.allowsPort(port) {
				continue
			}
			out = append(out, probe)
		}
	}

	return out
}

// FallbackProbes returns the legacy unfiltered fallback set.
func (c *ProbeCatalog) FallbackProbes() []ProbeSpec {
	return c.FallbackProbesFor(0, nil)
}

// FallbackProbesFor returns context-aware fallback probes to try when no
// port-specific probes match. Stateful protocols are only returned when
// existing hints already point at that protocol family.
func (c *ProbeCatalog) FallbackProbesFor(port int, hints []string) []ProbeSpec {
	if c == nil || len(c.FallbackProbeIDs) == 0 {
		return nil
	}

	normalizedHints := normalizeHints(hints)
	out := make([]ProbeSpec, 0, len(c.FallbackProbeIDs))
	for _, id := range c.FallbackProbeIDs {
		probe := c.findProbeByID(id)
		if probe == nil {
			continue
		}
		if !shouldIncludeFallbackProbe(*probe, normalizedHints) {
			continue
		}
		out = append(out, *probe)
	}
	return out
}

// findProbeByID searches all groups for a probe with the given ID.
func (c *ProbeCatalog) findProbeByID(id string) *ProbeSpec {
	for _, group := range c.Groups {
		for i := range group.Probes {
			if group.Probes[i].ID == id {
				return &group.Probes[i]
			}
		}
	}
	return nil
}

func (g ProbeGroup) matches(port int, hints map[string]struct{}) bool {
	if len(g.PortHints) > 0 && !containsInt(g.PortHints, port) {
		return false
	}

	if len(g.ProtocolHints) == 0 {
		return true
	}

	if hints == nil {
		// Port matched but we have no protocol hints; still allow match so long as port hint existed.
		if len(g.PortHints) > 0 {
			return true
		}
		return false
	}

	for _, hint := range g.ProtocolHints {
		if _, ok := hints[strings.ToLower(hint)]; ok {
			return true
		}
	}
	return false
}

func (p ProbeSpec) allowsPort(port int) bool {
	if len(p.PortInclude) > 0 && !containsInt(p.PortInclude, port) {
		return false
	}
	if len(p.PortExclude) > 0 && containsInt(p.PortExclude, port) {
		return false
	}
	return true
}

func containsInt(list []int, target int) bool {
	return slices.Contains(list, target)
}

func normalizeHints(hints []string) map[string]struct{} {
	if len(hints) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(hints))
	for _, hint := range hints {
		if hint == "" {
			continue
		}
		out[strings.ToLower(hint)] = struct{}{}
	}
	return out
}

func shouldIncludeFallbackProbe(probe ProbeSpec, hints map[string]struct{}) bool {
	switch strings.ToLower(strings.TrimSpace(probe.Protocol)) {
	case "ftp":
		return hasAnyHint(hints, "ftp", "ftps")
	case "redis":
		return hasAnyHint(hints, "redis", "memcached")
	default:
		return true
	}
}

func hasAnyHint(hints map[string]struct{}, expected ...string) bool {
	if len(hints) == 0 {
		return false
	}
	for _, hint := range expected {
		if _, ok := hints[hint]; ok {
			return true
		}
	}
	return false
}

// Validate ensures catalog content is well-formed.
func (c *ProbeCatalog) Validate() error {
	if c == nil {
		return fmt.Errorf("catalog is nil")
	}
	for i, group := range c.Groups {
		if group.ID == "" {
			return fmt.Errorf("probe group at index %d is missing id", i)
		}
		if len(group.Probes) == 0 {
			return fmt.Errorf("probe group %q has no probes", group.ID)
		}
		for j, probe := range group.Probes {
			if probe.ID == "" {
				return fmt.Errorf("group %q probe at index %d is missing id", group.ID, j)
			}
			if probe.Protocol == "" {
				return fmt.Errorf("probe %q missing protocol", probe.ID)
			}
			if probe.Payload == "" {
				return fmt.Errorf("probe %q missing payload", probe.ID)
			}
		}
	}
	return nil
}
