package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	parsepkg "github.com/cyprob/cyprob/pkg/modules/parse"
	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

type scanDebugTargetOptions struct {
	Ports   string
	Timeout string
	Format  string
}

type scanDebugResolvedTarget struct {
	Input string `json:"input"`
	IP    string `json:"ip"`
}

type scanDebugStep struct {
	Step     string   `json:"step"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

type scanDebugPayload struct {
	Target          string                             `json:"target"`
	ResolvedTargets []scanDebugResolvedTarget          `json:"resolved_targets"`
	OpenPorts       []discovery.TCPPortDiscoveryResult `json:"open_ports"`
	Banners         []scanpkg.BannerGrabResult         `json:"banners"`
	Fingerprints    []parsepkg.FingerprintParsedInfo   `json:"fingerprints"`
	TechTags        []parsepkg.TechTagResult           `json:"tech_tags"`
	Steps           []scanDebugStep                    `json:"steps"`
}

const (
	scanDebugOutputFormatJSON   = "json"
	scanDebugOutputFormatPretty = "pretty"
)

func NewScanDebugCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "scan-debug",
		Short:   "Internal debug commands for scan pipeline outputs",
		GroupID: "scan",
		Hidden:  true,
	}

	cmd.AddCommand(newScanDebugTargetCommand())
	return cmd
}

func newScanDebugTargetCommand() *cobra.Command {
	opts := scanDebugTargetOptions{}

	cmd := &cobra.Command{
		Use:   "target <host-or-ip>",
		Short: "Run discovery->banner->fingerprint->tech-tags pipeline and print debug output",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScanDebugTarget(cmd, args[0], opts)
		},
	}

	cmd.Flags().StringVar(&opts.Ports, "ports", "", "Ports to scan (e.g. 80,443,993)")
	cmd.Flags().StringVar(&opts.Timeout, "timeout", "", "Step timeout override (e.g. 5s)")
	cmd.Flags().StringVar(&opts.Format, "format", scanDebugOutputFormatJSON, "Output format: json|pretty")

	return cmd
}

func runScanDebugTarget(cmd *cobra.Command, target string, opts scanDebugTargetOptions) error {
	format, err := validateScanDebugOptions(opts)
	if err != nil {
		return err
	}

	steps := newScanDebugSteps(
		"resolve-targets",
		"tcp-port-discovery",
		"banner-grabber",
		"fingerprint-parser",
		"tech-tagger",
	)

	resolved, resolveErr := resolveDebugTargets(target)
	if resolveErr != nil {
		steps.addError("resolve-targets", resolveErr.Error())
		payload := scanDebugPayload{
			Target:          target,
			ResolvedTargets: nil,
			Steps:           steps.values(),
		}
		return writeScanDebugOutput(cmd.OutOrStdout(), format, payload)
	}
	if len(resolved) == 0 {
		steps.addWarning("resolve-targets", "no IPs resolved for target")
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	openPorts, err := runDebugTCPPortDiscoveryStage(ctx, target, opts, steps)
	if err != nil {
		return err
	}
	banners, err := runDebugBannerGrabStage(ctx, target, opts, steps, openPorts)
	if err != nil {
		return err
	}
	fingerprints, err := runDebugFingerprintStage(ctx, steps, banners)
	if err != nil {
		return err
	}
	techTags, err := runDebugTechTagStage(ctx, steps, banners, fingerprints)
	if err != nil {
		return err
	}

	payload := scanDebugPayload{
		Target:          target,
		ResolvedTargets: resolved,
		OpenPorts:       openPorts,
		Banners:         banners,
		Fingerprints:    fingerprints,
		TechTags:        techTags,
		Steps:           steps.values(),
	}

	return writeScanDebugOutput(cmd.OutOrStdout(), format, payload)
}

func validateScanDebugOptions(opts scanDebugTargetOptions) (string, error) {
	if opts.Timeout != "" {
		if _, err := time.ParseDuration(opts.Timeout); err != nil {
			return "", fmt.Errorf("invalid --timeout value %q: %w", opts.Timeout, err)
		}
	}

	format := strings.ToLower(strings.TrimSpace(opts.Format))
	if format != scanDebugOutputFormatJSON && format != scanDebugOutputFormatPretty {
		return "", fmt.Errorf("unsupported --format %q (use json or pretty)", opts.Format)
	}
	return format, nil
}

func runDebugTCPPortDiscoveryStage(
	ctx context.Context,
	target string,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
) ([]discovery.TCPPortDiscoveryResult, error) {
	tcpCfg := map[string]any{}
	if strings.TrimSpace(opts.Ports) != "" {
		tcpCfg["ports"] = splitAndTrim(opts.Ports)
	}
	if opts.Timeout != "" {
		tcpCfg["timeout"] = opts.Timeout
	}

	tcpModule, err := engine.GetModuleInstance("scan_debug_tcp_port_discovery", "tcp-port-discovery", tcpCfg)
	if err != nil {
		return nil, fmt.Errorf("create tcp-port-discovery module: %w", err)
	}

	tcpOutputs, tcpExecErr := executeDebugModule(ctx, tcpModule, map[string]any{
		"config.targets": []string{target},
	})
	if tcpExecErr != nil {
		steps.addError("tcp-port-discovery", tcpExecErr.Error())
	}
	steps.addErrors("tcp-port-discovery", collectOutputErrors(tcpOutputs))
	openPorts := collectTCPDiscoveryResults(tcpOutputs)
	if len(openPorts) == 0 {
		steps.addWarning("tcp-port-discovery", "no open ports found")
	}
	return openPorts, nil
}

func runDebugBannerGrabStage(
	ctx context.Context,
	target string,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	openPorts []discovery.TCPPortDiscoveryResult,
) ([]scanpkg.BannerGrabResult, error) {
	bannerCfg := map[string]any{}
	if opts.Timeout != "" {
		bannerCfg["read_timeout"] = opts.Timeout
		bannerCfg["connect_timeout"] = opts.Timeout
	}

	bannerModule, err := engine.GetModuleInstance("scan_debug_banner_grabber", "banner-grabber", bannerCfg)
	if err != nil {
		return nil, fmt.Errorf("create banner-grabber module: %w", err)
	}

	bannerInputs := map[string]any{
		"discovery.open_tcp_ports":    toAnySlice(openPorts),
		"config.original_cli_targets": []string{target},
	}
	bannerOutputs, bannerExecErr := executeDebugModule(ctx, bannerModule, bannerInputs)
	if bannerExecErr != nil {
		steps.addError("banner-grabber", bannerExecErr.Error())
	}
	steps.addErrors("banner-grabber", collectOutputErrors(bannerOutputs))
	banners := collectBannerResults(bannerOutputs)
	if len(banners) == 0 {
		steps.addWarning("banner-grabber", "no banners captured")
	}
	steps.addWarnings("banner-grabber", bannerWarnings(banners))
	return banners, nil
}

func runDebugFingerprintStage(
	ctx context.Context,
	steps *scanDebugStepCollection,
	banners []scanpkg.BannerGrabResult,
) ([]parsepkg.FingerprintParsedInfo, error) {
	fingerprintModule, err := engine.GetModuleInstance("scan_debug_fingerprint_parser", "fingerprint-parser", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("create fingerprint-parser module: %w", err)
	}

	fingerprintOutputs, fingerprintExecErr := executeDebugModule(ctx, fingerprintModule, map[string]any{
		"service.banner.tcp": toAnySlice(banners),
	})
	if fingerprintExecErr != nil {
		steps.addError("fingerprint-parser", fingerprintExecErr.Error())
	}
	steps.addErrors("fingerprint-parser", collectOutputErrors(fingerprintOutputs))
	fingerprints := collectFingerprintResults(fingerprintOutputs)
	if len(fingerprints) == 0 {
		steps.addWarning("fingerprint-parser", "no fingerprint matches")
	}
	return fingerprints, nil
}

func runDebugTechTagStage(
	ctx context.Context,
	steps *scanDebugStepCollection,
	banners []scanpkg.BannerGrabResult,
	fingerprints []parsepkg.FingerprintParsedInfo,
) ([]parsepkg.TechTagResult, error) {
	techModule, err := engine.GetModuleInstance("scan_debug_tech_tagger", "tech-tagger", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("create tech-tagger module: %w", err)
	}

	techOutputs, techExecErr := executeDebugModule(ctx, techModule, map[string]any{
		"service.banner.tcp":          toAnySlice(banners),
		"service.fingerprint.details": toAnySlice(fingerprints),
	})
	if techExecErr != nil {
		steps.addError("tech-tagger", techExecErr.Error())
	}
	steps.addErrors("tech-tagger", collectOutputErrors(techOutputs))
	techTags := collectTechTagResults(techOutputs)
	if len(techTags) == 0 {
		steps.addWarning("tech-tagger", "no tech tags generated")
	}
	return techTags, nil
}

func executeDebugModule(ctx context.Context, module engine.Module, inputs map[string]any) ([]engine.ModuleOutput, error) {
	outputChan := make(chan engine.ModuleOutput, 256)
	execDone := make(chan error, 1)
	outputs := make([]engine.ModuleOutput, 0, 32)

	go func() {
		err := module.Execute(ctx, inputs, outputChan)
		close(outputChan)
		execDone <- err
		close(execDone)
	}()

	for output := range outputChan {
		outputs = append(outputs, output)
	}

	return outputs, <-execDone
}

func collectOutputErrors(outputs []engine.ModuleOutput) []string {
	errs := make([]string, 0)
	for _, output := range outputs {
		if output.Error != nil {
			errs = append(errs, output.Error.Error())
		}
	}
	return uniqueStrings(errs)
}

func collectTCPDiscoveryResults(outputs []engine.ModuleOutput) []discovery.TCPPortDiscoveryResult {
	results := make([]discovery.TCPPortDiscoveryResult, 0)
	for _, output := range outputs {
		switch data := output.Data.(type) {
		case discovery.TCPPortDiscoveryResult:
			results = append(results, data)
		case []discovery.TCPPortDiscoveryResult:
			results = append(results, data...)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Target < results[j].Target
	})
	return results
}

func collectBannerResults(outputs []engine.ModuleOutput) []scanpkg.BannerGrabResult {
	results := make([]scanpkg.BannerGrabResult, 0)
	for _, output := range outputs {
		switch data := output.Data.(type) {
		case scanpkg.BannerGrabResult:
			results = append(results, data)
		case []scanpkg.BannerGrabResult:
			results = append(results, data...)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].IP == results[j].IP {
			return results[i].Port < results[j].Port
		}
		return results[i].IP < results[j].IP
	})
	return results
}

func collectFingerprintResults(outputs []engine.ModuleOutput) []parsepkg.FingerprintParsedInfo {
	results := make([]parsepkg.FingerprintParsedInfo, 0)
	for _, output := range outputs {
		switch data := output.Data.(type) {
		case parsepkg.FingerprintParsedInfo:
			results = append(results, data)
		case []parsepkg.FingerprintParsedInfo:
			results = append(results, data...)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Target == results[j].Target {
			return results[i].Port < results[j].Port
		}
		return results[i].Target < results[j].Target
	})
	return results
}

func collectTechTagResults(outputs []engine.ModuleOutput) []parsepkg.TechTagResult {
	results := make([]parsepkg.TechTagResult, 0)
	for _, output := range outputs {
		switch data := output.Data.(type) {
		case parsepkg.TechTagResult:
			results = append(results, data)
		case []parsepkg.TechTagResult:
			results = append(results, data...)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Target == results[j].Target {
			return results[i].Port < results[j].Port
		}
		return results[i].Target < results[j].Target
	})
	return results
}

func resolveDebugTargets(target string) ([]scanDebugResolvedTarget, error) {
	if ip := net.ParseIP(target); ip != nil {
		return []scanDebugResolvedTarget{{Input: target, IP: ip.String()}}, nil
	}

	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, err
	}

	results := make([]scanDebugResolvedTarget, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		ipStr := ip.String()
		if v4 := ip.To4(); v4 != nil {
			ipStr = v4.String()
		}
		if _, exists := seen[ipStr]; exists {
			continue
		}
		seen[ipStr] = struct{}{}
		results = append(results, scanDebugResolvedTarget{Input: target, IP: ipStr})
	}

	sort.Slice(results, func(i, j int) bool { return results[i].IP < results[j].IP })
	return results, nil
}

func splitAndTrim(value string) []string {
	parts := strings.Split(value, ",")
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			clean = append(clean, trimmed)
		}
	}
	return clean
}

func toAnySlice[T any](items []T) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	return out
}

func bannerWarnings(banners []scanpkg.BannerGrabResult) []string {
	warnings := make([]string, 0)
	for _, banner := range banners {
		if banner.Error != "" {
			warnings = append(warnings, fmt.Sprintf("%s:%d %s", banner.IP, banner.Port, banner.Error))
		} else if strings.TrimSpace(banner.Banner) == "" {
			warnings = append(warnings, fmt.Sprintf("%s:%d empty banner", banner.IP, banner.Port))
		}
	}
	return uniqueStrings(warnings)
}

func writeScanDebugOutput(w io.Writer, format string, payload scanDebugPayload) error {
	if format == "pretty" {
		return writeScanDebugPretty(w, payload)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func writeScanDebugPretty(w io.Writer, payload scanDebugPayload) error {
	fmt.Fprintf(w, "Target: %s\n", payload.Target)
	fmt.Fprintf(w, "Resolved Targets: %d\n", len(payload.ResolvedTargets))
	fmt.Fprintf(w, "Open Port Entries: %d\n", len(payload.OpenPorts))
	fmt.Fprintf(w, "Banners: %d\n", len(payload.Banners))
	fmt.Fprintf(w, "Fingerprints: %d\n", len(payload.Fingerprints))
	fmt.Fprintf(w, "Tech Tags: %d\n", len(payload.TechTags))
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Step Status:")
	for _, step := range payload.Steps {
		fmt.Fprintf(w, "- %s\n", step.Step)
		fmt.Fprintf(w, "  errors: %d\n", len(step.Errors))
		fmt.Fprintf(w, "  warnings: %d\n", len(step.Warnings))
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "JSON:")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

type scanDebugStepCollection struct {
	order []string
	steps map[string]*scanDebugStep
}

func newScanDebugSteps(stepNames ...string) *scanDebugStepCollection {
	c := &scanDebugStepCollection{
		order: make([]string, 0, len(stepNames)),
		steps: make(map[string]*scanDebugStep, len(stepNames)),
	}
	for _, stepName := range stepNames {
		c.order = append(c.order, stepName)
		c.steps[stepName] = &scanDebugStep{
			Step:     stepName,
			Errors:   []string{},
			Warnings: []string{},
		}
	}
	return c
}

func (c *scanDebugStepCollection) addError(step, message string) {
	s, ok := c.steps[step]
	if !ok {
		return
	}
	if strings.TrimSpace(message) == "" {
		return
	}
	if !slices.Contains(s.Errors, message) {
		s.Errors = append(s.Errors, message)
	}
}

func (c *scanDebugStepCollection) addWarning(step, message string) {
	s, ok := c.steps[step]
	if !ok {
		return
	}
	if strings.TrimSpace(message) == "" {
		return
	}
	if !slices.Contains(s.Warnings, message) {
		s.Warnings = append(s.Warnings, message)
	}
}

func (c *scanDebugStepCollection) addErrors(step string, messages []string) {
	for _, message := range messages {
		c.addError(step, message)
	}
}

func (c *scanDebugStepCollection) addWarnings(step string, messages []string) {
	for _, message := range messages {
		c.addWarning(step, message)
	}
}

func (c *scanDebugStepCollection) values() []scanDebugStep {
	out := make([]scanDebugStep, 0, len(c.order))
	for _, stepName := range c.order {
		step := c.steps[stepName]
		out = append(out, scanDebugStep{
			Step:     step.Step,
			Errors:   append([]string(nil), step.Errors...),
			Warnings: append([]string(nil), step.Warnings...),
		})
	}
	return out
}

func uniqueStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
