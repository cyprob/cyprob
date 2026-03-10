package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"strconv"
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
	SMTPDetails     []scanpkg.SMTPServiceInfo          `json:"smtp_details"`
	SSHDetails      []scanpkg.SSHServiceInfo           `json:"ssh_details"`
	RPCEpmapper     []scanpkg.RPCEpmapperInfo          `json:"rpc_epmapper"`
	RPCDetails      []scanpkg.RPCServiceInfo           `json:"rpc_details"`
	RDPDetails      []scanpkg.RDPServiceInfo           `json:"rdp_details"`
	TLSDetails      []scanpkg.TLSServiceInfo           `json:"tls_details"`
	SMBDetails      []scanpkg.SMBServiceInfo           `json:"smb_details"`
	ServiceIdentity []parsepkg.ServiceIdentityInfo     `json:"service_identity"`
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
		"smtp-native-probe",
		"ssh-native-probe",
		"rpc-epmapper-probe",
		"rpc-followup-probe",
		"rdp-native-probe",
		"tls-native-probe",
		"smb-native-probe",
		"fingerprint-parser",
		"tech-tagger",
		"service-identity-normalizer",
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
	smtpDetails, err := runDebugSMTPNativeProbeStage(ctx, opts, steps, openPorts, banners)
	if err != nil {
		return err
	}
	sshDetails, err := runDebugSSHNativeProbeStage(ctx, opts, steps, openPorts, banners)
	if err != nil {
		return err
	}
	rpcEpmapper, err := runDebugRPCEpmapperStage(ctx, opts, steps, openPorts)
	if err != nil {
		return err
	}
	rpcDetails, err := runDebugRPCFollowupStage(ctx, opts, steps, rpcEpmapper)
	if err != nil {
		return err
	}
	rdpDetails, err := runDebugRDPNativeProbeStage(ctx, opts, steps, openPorts, nil)
	if err != nil {
		return err
	}
	tlsDetails, err := runDebugTLSNativeProbeStage(ctx, opts, steps, openPorts)
	if err != nil {
		return err
	}
	smbDetails, err := runDebugSMBNativeProbeStage(ctx, opts, steps, openPorts, nil)
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
	serviceIdentity, err := runDebugServiceIdentityStage(
		ctx,
		steps,
		banners,
		fingerprints,
		techTags,
		smtpDetails,
		sshDetails,
		smbDetails,
		rdpDetails,
		rpcDetails,
		tlsDetails,
	)
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
		SMTPDetails:     smtpDetails,
		SSHDetails:      sshDetails,
		RPCEpmapper:     rpcEpmapper,
		RPCDetails:      rpcDetails,
		RDPDetails:      rdpDetails,
		TLSDetails:      tlsDetails,
		SMBDetails:      smbDetails,
		ServiceIdentity: serviceIdentity,
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

func runDebugRPCEpmapperStage(
	ctx context.Context,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	openPorts []discovery.TCPPortDiscoveryResult,
) ([]scanpkg.RPCEpmapperInfo, error) {
	rpcConfig := map[string]any{}
	if opts.Timeout != "" {
		rpcConfig["timeout"] = opts.Timeout
		rpcConfig["connect_timeout"] = opts.Timeout
		rpcConfig["io_timeout"] = opts.Timeout
	}

	rpcModule, err := engine.GetModuleInstance("scan_debug_rpc_epmapper_probe", "rpc-epmapper-probe", rpcConfig)
	if err != nil {
		return nil, fmt.Errorf("create rpc-epmapper-probe module: %w", err)
	}

	rpcOutputs, rpcExecErr := executeDebugModule(ctx, rpcModule, map[string]any{
		"discovery.open_tcp_ports": toAnySlice(openPorts),
	})
	if rpcExecErr != nil {
		steps.addError("rpc-epmapper-probe", rpcExecErr.Error())
	}
	steps.addErrors("rpc-epmapper-probe", collectOutputErrors(rpcOutputs))
	results := collectRPCEpmapperResults(rpcOutputs)
	if len(results) == 0 {
		steps.addWarning("rpc-epmapper-probe", "no rpc epmapper metadata generated")
	}
	return results, nil
}

func runDebugSMTPNativeProbeStage(
	ctx context.Context,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	openPorts []discovery.TCPPortDiscoveryResult,
	banners []scanpkg.BannerGrabResult,
) ([]scanpkg.SMTPServiceInfo, error) {
	smtpConfig := map[string]any{}
	if opts.Timeout != "" {
		smtpConfig["timeout"] = opts.Timeout
		smtpConfig["connect_timeout"] = opts.Timeout
		smtpConfig["io_timeout"] = opts.Timeout
		smtpConfig["retries"] = 0
	}
	if strings.TrimSpace(opts.Ports) != "" {
		candidatePorts := make([]int, 0, 4)
		for _, item := range splitAndTrim(opts.Ports) {
			port, convErr := strconv.Atoi(item)
			if convErr != nil || port <= 0 || port > 65535 {
				continue
			}
			candidatePorts = append(candidatePorts, port)
		}
		if len(candidatePorts) > 0 {
			smtpConfig["candidate_ports"] = candidatePorts
		}
	}

	smtpModule, err := engine.GetModuleInstance("scan_debug_smtp_native_probe", "smtp-native-probe", smtpConfig)
	if err != nil {
		return nil, fmt.Errorf("create smtp-native-probe module: %w", err)
	}

	smtpOutputs, smtpExecErr := executeDebugModule(ctx, smtpModule, map[string]any{
		"discovery.open_tcp_ports": toAnySlice(openPorts),
		"service.banner.tcp":       toAnySlice(banners),
	})
	if smtpExecErr != nil {
		steps.addError("smtp-native-probe", smtpExecErr.Error())
	}
	steps.addErrors("smtp-native-probe", collectOutputErrors(smtpOutputs))
	results := collectSMTPDetailsResults(smtpOutputs)
	if len(results) == 0 {
		steps.addWarning("smtp-native-probe", "no smtp metadata generated")
	}
	return results, nil
}

func runDebugSSHNativeProbeStage(
	ctx context.Context,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	openPorts []discovery.TCPPortDiscoveryResult,
	banners []scanpkg.BannerGrabResult,
) ([]scanpkg.SSHServiceInfo, error) {
	sshConfig := map[string]any{}
	if opts.Timeout != "" {
		sshConfig["timeout"] = opts.Timeout
		sshConfig["connect_timeout"] = opts.Timeout
		sshConfig["io_timeout"] = opts.Timeout
		sshConfig["retries"] = 0
	}
	if strings.TrimSpace(opts.Ports) != "" {
		candidatePorts := make([]int, 0, 4)
		for _, item := range splitAndTrim(opts.Ports) {
			port, convErr := strconv.Atoi(item)
			if convErr != nil || port <= 0 || port > 65535 {
				continue
			}
			candidatePorts = append(candidatePorts, port)
		}
		if len(candidatePorts) > 0 {
			sshConfig["candidate_ports"] = candidatePorts
		}
	}

	sshModule, err := engine.GetModuleInstance("scan_debug_ssh_native_probe", "ssh-native-probe", sshConfig)
	if err != nil {
		return nil, fmt.Errorf("create ssh-native-probe module: %w", err)
	}

	sshOutputs, sshExecErr := executeDebugModule(ctx, sshModule, map[string]any{
		"discovery.open_tcp_ports": toAnySlice(openPorts),
		"service.banner.tcp":       toAnySlice(banners),
	})
	if sshExecErr != nil {
		steps.addError("ssh-native-probe", sshExecErr.Error())
	}
	steps.addErrors("ssh-native-probe", collectOutputErrors(sshOutputs))
	results := collectSSHDetailsResults(sshOutputs)
	if len(results) == 0 {
		steps.addWarning("ssh-native-probe", "no ssh metadata generated")
	}
	return results, nil
}

func runDebugRPCFollowupStage(
	ctx context.Context,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	rpcEpmapper []scanpkg.RPCEpmapperInfo,
) ([]scanpkg.RPCServiceInfo, error) {
	rpcConfig := map[string]any{}
	if opts.Timeout != "" {
		rpcConfig["host_total_timeout"] = opts.Timeout
		rpcConfig["per_port_total_timeout"] = opts.Timeout
		rpcConfig["connect_timeout"] = opts.Timeout
		rpcConfig["io_timeout"] = opts.Timeout
	}

	rpcModule, err := engine.GetModuleInstance("scan_debug_rpc_followup_probe", "rpc-followup-probe", rpcConfig)
	if err != nil {
		return nil, fmt.Errorf("create rpc-followup-probe module: %w", err)
	}

	rpcOutputs, rpcExecErr := executeDebugModule(ctx, rpcModule, map[string]any{
		"service.rpc.epmapper": toAnySlice(rpcEpmapper),
	})
	if rpcExecErr != nil {
		steps.addError("rpc-followup-probe", rpcExecErr.Error())
	}
	steps.addErrors("rpc-followup-probe", collectOutputErrors(rpcOutputs))
	results := collectRPCDetailsResults(rpcOutputs)
	if len(results) == 0 {
		steps.addWarning("rpc-followup-probe", "no rpc follow-up metadata generated")
	}
	return results, nil
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

func runDebugSMBNativeProbeStage(
	ctx context.Context,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	openPorts []discovery.TCPPortDiscoveryResult,
	banners []scanpkg.BannerGrabResult,
) ([]scanpkg.SMBServiceInfo, error) {
	smbConfig := map[string]any{}
	if opts.Timeout != "" {
		smbConfig["timeout"] = opts.Timeout
		smbConfig["connect_timeout"] = opts.Timeout
		smbConfig["io_timeout"] = opts.Timeout
		smbConfig["retries"] = 1
	}

	smbModule, err := engine.GetModuleInstance("scan_debug_smb_native_probe", "smb-native-probe", smbConfig)
	if err != nil {
		return nil, fmt.Errorf("create smb-native-probe module: %w", err)
	}

	smbOutputs, smbExecErr := executeDebugModule(ctx, smbModule, map[string]any{
		"discovery.open_tcp_ports": toAnySlice(openPorts),
		"service.banner.tcp":       toAnySlice(banners),
	})
	if smbExecErr != nil {
		steps.addError("smb-native-probe", smbExecErr.Error())
	}
	steps.addErrors("smb-native-probe", collectOutputErrors(smbOutputs))
	smbDetails := collectSMBDetailsResults(smbOutputs)
	if len(smbDetails) == 0 {
		steps.addWarning("smb-native-probe", "no smb metadata generated")
	}
	return smbDetails, nil
}

func runDebugRDPNativeProbeStage(
	ctx context.Context,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	openPorts []discovery.TCPPortDiscoveryResult,
	banners []scanpkg.BannerGrabResult,
) ([]scanpkg.RDPServiceInfo, error) {
	rdpConfig := map[string]any{}
	if opts.Timeout != "" {
		rdpConfig["timeout"] = opts.Timeout
		rdpConfig["connect_timeout"] = opts.Timeout
		rdpConfig["io_timeout"] = opts.Timeout
		rdpConfig["retries"] = 0
	}

	rdpModule, err := engine.GetModuleInstance("scan_debug_rdp_native_probe", "rdp-native-probe", rdpConfig)
	if err != nil {
		return nil, fmt.Errorf("create rdp-native-probe module: %w", err)
	}

	rdpOutputs, rdpExecErr := executeDebugModule(ctx, rdpModule, map[string]any{
		"discovery.open_tcp_ports": toAnySlice(openPorts),
		"service.banner.tcp":       toAnySlice(banners),
	})
	if rdpExecErr != nil {
		steps.addError("rdp-native-probe", rdpExecErr.Error())
	}
	steps.addErrors("rdp-native-probe", collectOutputErrors(rdpOutputs))
	rdpDetails := collectRDPDetailsResults(rdpOutputs)
	if len(rdpDetails) == 0 {
		steps.addWarning("rdp-native-probe", "no rdp metadata generated")
	}
	return rdpDetails, nil
}

func runDebugTLSNativeProbeStage(
	ctx context.Context,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	openPorts []discovery.TCPPortDiscoveryResult,
) ([]scanpkg.TLSServiceInfo, error) {
	tlsConfig := map[string]any{}
	if opts.Timeout != "" {
		tlsConfig["timeout"] = opts.Timeout
		tlsConfig["connect_timeout"] = opts.Timeout
		tlsConfig["io_timeout"] = opts.Timeout
		tlsConfig["retries"] = 0
	}
	if strings.TrimSpace(opts.Ports) != "" {
		ports := splitAndTrim(opts.Ports)
		extraPorts := make([]int, 0, len(ports))
		for _, portText := range ports {
			port, convErr := strconv.Atoi(strings.TrimSpace(portText))
			if convErr == nil && port > 0 && port <= 65535 {
				extraPorts = append(extraPorts, port)
			}
		}
		if len(extraPorts) > 0 {
			tlsConfig["extra_ports"] = extraPorts
		}
	}

	tlsModule, err := engine.GetModuleInstance("scan_debug_tls_native_probe", "tls-native-probe", tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("create tls-native-probe module: %w", err)
	}

	tlsOutputs, tlsExecErr := executeDebugModule(ctx, tlsModule, map[string]any{
		"discovery.open_tcp_ports": toAnySlice(openPorts),
	})
	if tlsExecErr != nil {
		steps.addError("tls-native-probe", tlsExecErr.Error())
	}
	steps.addErrors("tls-native-probe", collectOutputErrors(tlsOutputs))
	tlsDetails := collectTLSDetailsResults(tlsOutputs)
	if len(tlsDetails) == 0 {
		steps.addWarning("tls-native-probe", "no tls metadata generated")
	}
	return tlsDetails, nil
}

func runDebugServiceIdentityStage(
	ctx context.Context,
	steps *scanDebugStepCollection,
	banners []scanpkg.BannerGrabResult,
	fingerprints []parsepkg.FingerprintParsedInfo,
	techTags []parsepkg.TechTagResult,
	smtpDetails []scanpkg.SMTPServiceInfo,
	sshDetails []scanpkg.SSHServiceInfo,
	smbDetails []scanpkg.SMBServiceInfo,
	rdpDetails []scanpkg.RDPServiceInfo,
	rpcDetails []scanpkg.RPCServiceInfo,
	tlsDetails []scanpkg.TLSServiceInfo,
) ([]parsepkg.ServiceIdentityInfo, error) {
	normalizerModule, err := engine.GetModuleInstance("scan_debug_service_identity_normalizer", "service-identity-normalizer", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("create service-identity-normalizer module: %w", err)
	}

	normalizerOutputs, normalizerExecErr := executeDebugModule(ctx, normalizerModule, map[string]any{
		"service.banner.tcp":          toAnySlice(banners),
		"service.fingerprint.details": toAnySlice(fingerprints),
		"service.tech.tags":           toAnySlice(techTags),
		"service.smtp.details":        toAnySlice(smtpDetails),
		"service.ssh.details":         toAnySlice(sshDetails),
		"service.smb.details":         toAnySlice(smbDetails),
		"service.rdp.details":         toAnySlice(rdpDetails),
		"service.rpc.details":         toAnySlice(rpcDetails),
		"service.tls.details":         toAnySlice(tlsDetails),
	})
	if normalizerExecErr != nil {
		steps.addError("service-identity-normalizer", normalizerExecErr.Error())
	}
	steps.addErrors("service-identity-normalizer", collectOutputErrors(normalizerOutputs))
	serviceIdentity := collectServiceIdentityResults(normalizerOutputs)
	if len(serviceIdentity) == 0 {
		steps.addWarning("service-identity-normalizer", "no canonical service identity generated")
	}
	return serviceIdentity, nil
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

func collectSMBDetailsResults(outputs []engine.ModuleOutput) []scanpkg.SMBServiceInfo {
	results := make([]scanpkg.SMBServiceInfo, 0)
	for _, output := range outputs {
		switch data := output.Data.(type) {
		case scanpkg.SMBServiceInfo:
			results = append(results, data)
		case []scanpkg.SMBServiceInfo:
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

func collectSSHDetailsResults(outputs []engine.ModuleOutput) []scanpkg.SSHServiceInfo {
	results := make([]scanpkg.SSHServiceInfo, 0)
	for _, output := range outputs {
		switch data := output.Data.(type) {
		case scanpkg.SSHServiceInfo:
			results = append(results, data)
		case []scanpkg.SSHServiceInfo:
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

func collectSMTPDetailsResults(outputs []engine.ModuleOutput) []scanpkg.SMTPServiceInfo {
	results := make([]scanpkg.SMTPServiceInfo, 0)
	for _, output := range outputs {
		switch data := output.Data.(type) {
		case scanpkg.SMTPServiceInfo:
			results = append(results, data)
		case []scanpkg.SMTPServiceInfo:
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

func collectRPCEpmapperResults(outputs []engine.ModuleOutput) []scanpkg.RPCEpmapperInfo {
	results := make([]scanpkg.RPCEpmapperInfo, 0)
	for _, output := range outputs {
		switch data := output.Data.(type) {
		case scanpkg.RPCEpmapperInfo:
			results = append(results, data)
		case []scanpkg.RPCEpmapperInfo:
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

func collectRPCDetailsResults(outputs []engine.ModuleOutput) []scanpkg.RPCServiceInfo {
	results := make([]scanpkg.RPCServiceInfo, 0)
	for _, output := range outputs {
		switch data := output.Data.(type) {
		case scanpkg.RPCServiceInfo:
			results = append(results, data)
		case []scanpkg.RPCServiceInfo:
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

func collectRDPDetailsResults(outputs []engine.ModuleOutput) []scanpkg.RDPServiceInfo {
	results := make([]scanpkg.RDPServiceInfo, 0)
	for _, output := range outputs {
		switch data := output.Data.(type) {
		case scanpkg.RDPServiceInfo:
			results = append(results, data)
		case []scanpkg.RDPServiceInfo:
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

func collectTLSDetailsResults(outputs []engine.ModuleOutput) []scanpkg.TLSServiceInfo {
	results := make([]scanpkg.TLSServiceInfo, 0)
	for _, output := range outputs {
		switch data := output.Data.(type) {
		case scanpkg.TLSServiceInfo:
			results = append(results, data)
		case []scanpkg.TLSServiceInfo:
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

func collectServiceIdentityResults(outputs []engine.ModuleOutput) []parsepkg.ServiceIdentityInfo {
	results := make([]parsepkg.ServiceIdentityInfo, 0)
	for _, output := range outputs {
		switch data := output.Data.(type) {
		case parsepkg.ServiceIdentityInfo:
			results = append(results, data)
		case []parsepkg.ServiceIdentityInfo:
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
	fmt.Fprintf(w, "SMTP Details: %d\n", len(payload.SMTPDetails))
	fmt.Fprintf(w, "SSH Details: %d\n", len(payload.SSHDetails))
	fmt.Fprintf(w, "RPC Epmapper: %d\n", len(payload.RPCEpmapper))
	fmt.Fprintf(w, "RPC Details: %d\n", len(payload.RPCDetails))
	fmt.Fprintf(w, "RDP Details: %d\n", len(payload.RDPDetails))
	fmt.Fprintf(w, "TLS Details: %d\n", len(payload.TLSDetails))
	fmt.Fprintf(w, "SMB Details: %d\n", len(payload.SMBDetails))
	fmt.Fprintf(w, "Service Identity: %d\n", len(payload.ServiceIdentity))
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
