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
	Ports    string
	UDPPorts string
	Timeout  string
	Format   string
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
	OpenUDPPorts    []discovery.UDPPortDiscoveryResult `json:"open_udp_ports,omitempty"`
	Banners         []scanpkg.BannerGrabResult         `json:"banners"`
	HTTPDetails     []parsepkg.HTTPParsedInfo          `json:"http_details,omitempty"`
	Fingerprints    []parsepkg.FingerprintParsedInfo   `json:"fingerprints"`
	TechTags        []parsepkg.TechTagResult           `json:"tech_tags"`
	SMTPDetails     []scanpkg.SMTPServiceInfo          `json:"smtp_details"`
	SSHDetails      []scanpkg.SSHServiceInfo           `json:"ssh_details"`
	SNMPDetails     []scanpkg.SNMPServiceInfo          `json:"snmp_details,omitempty"`
	RPCEpmapper     []scanpkg.RPCEpmapperInfo          `json:"rpc_epmapper"`
	RPCDetails      []scanpkg.RPCServiceInfo           `json:"rpc_details"`
	RDPDetails      []scanpkg.RDPServiceInfo           `json:"rdp_details"`
	TLSDetails      []scanpkg.TLSServiceInfo           `json:"tls_details"`
	SMBDetails      []scanpkg.SMBServiceInfo           `json:"smb_details"`
	AssetProfiles   []engine.AssetProfile              `json:"asset_profiles,omitempty"`
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
	cmd.Flags().StringVar(&opts.UDPPorts, "udp-ports", "", "UDP ports to scan (e.g. 161)")
	cmd.Flags().StringVar(&opts.Timeout, "timeout", "", "Step timeout override (e.g. 5s)")
	cmd.Flags().StringVar(&opts.Format, "format", scanDebugOutputFormatJSON, "Output format: json|pretty")

	return cmd
}

//nolint:gocyclo // Debug pipeline orchestration is intentionally linear and stage-oriented.
func runScanDebugTarget(cmd *cobra.Command, target string, opts scanDebugTargetOptions) error {
	format, err := validateScanDebugOptions(opts)
	if err != nil {
		return err
	}

	stepNames := []string{
		"resolve-targets",
		"tcp-port-discovery",
	}
	if strings.TrimSpace(opts.UDPPorts) != "" {
		stepNames = append(stepNames, "udp-port-discovery")
	}
	stepNames = append(stepNames,
		"banner-grabber",
		"smtp-native-probe",
		"ssh-native-probe",
	)
	if strings.TrimSpace(opts.UDPPorts) != "" {
		stepNames = append(stepNames, "snmp-native-probe")
	}
	stepNames = append(stepNames,
		"rpc-epmapper-probe",
		"rpc-followup-probe",
		"rdp-native-probe",
		"tls-native-probe",
		"smb-native-probe",
		"http-parser",
		"fingerprint-parser",
		"tech-tagger",
		"service-identity-normalizer",
		"asset-profile-builder",
	)
	steps := newScanDebugSteps(stepNames...)

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
	var openUDPPorts []discovery.UDPPortDiscoveryResult
	var snmpDetails []scanpkg.SNMPServiceInfo
	if strings.TrimSpace(opts.UDPPorts) != "" {
		openUDPPorts, err = runDebugUDPPortDiscoveryStage(ctx, target, opts, steps)
		if err != nil {
			return err
		}
		snmpDetails, err = runDebugSNMPNativeProbeStageWithModule(ctx, opts, steps, openUDPPorts, "scan_debug_snmp_native_probe", "snmp-native-probe", "snmp-native-probe")
		if err != nil {
			return err
		}
	}
	banners, err := runDebugBannerGrabStageWithModule(ctx, target, opts, steps, openPorts, "scan_debug_banner_grabber", "banner-grabber", "banner-grabber")
	if err != nil {
		return err
	}
	smtpDetails, err := runDebugSMTPNativeProbeStageWithModule(ctx, opts, steps, openPorts, banners, "scan_debug_smtp_native_probe", "smtp-native-probe", "smtp-native-probe")
	if err != nil {
		return err
	}
	sshDetails, err := runDebugSSHNativeProbeStageWithModule(ctx, opts, steps, openPorts, banners, "scan_debug_ssh_native_probe", "ssh-native-probe", "ssh-native-probe")
	if err != nil {
		return err
	}
	rpcEpmapper, err := runDebugRPCEpmapperStageWithModule(ctx, opts, steps, openPorts, "scan_debug_rpc_epmapper_probe", "rpc-epmapper-probe", "rpc-epmapper-probe")
	if err != nil {
		return err
	}
	rpcDetails, err := runDebugRPCFollowupStageWithModule(ctx, opts, steps, rpcEpmapper, "scan_debug_rpc_followup_probe", "rpc-followup-probe", "rpc-followup-probe")
	if err != nil {
		return err
	}
	rdpDetails, err := runDebugRDPNativeProbeStageWithModule(ctx, opts, steps, openPorts, nil, "scan_debug_rdp_native_probe", "rdp-native-probe", "rdp-native-probe")
	if err != nil {
		return err
	}
	tlsDetails, err := runDebugTLSNativeProbeStageWithModule(ctx, opts, steps, openPorts, banners, "scan_debug_tls_native_probe", "tls-native-probe", "tls-native-probe")
	if err != nil {
		return err
	}
	smbDetails, err := runDebugSMBNativeProbeStageWithModule(ctx, opts, steps, openPorts, nil, "scan_debug_smb_native_probe", "smb-native-probe", "smb-native-probe")
	if err != nil {
		return err
	}
	httpDetails, err := runDebugHTTPStageWithModule(ctx, steps, banners, "scan_debug_http_parser", "http-parser", "http-parser")
	if err != nil {
		return err
	}
	fingerprints, err := runDebugFingerprintStageWithModule(ctx, steps, banners, "scan_debug_fingerprint_parser", "fingerprint-parser", "fingerprint-parser")
	if err != nil {
		return err
	}
	techTags, err := runDebugTechTagStageWithModule(ctx, steps, banners, httpDetails, fingerprints, "scan_debug_tech_tagger", "tech-tagger", "tech-tagger")
	if err != nil {
		return err
	}
	pipelineInputs := map[string]any{
		"config.targets":              []string{target},
		"discovery.open_tcp_ports":    toAnySlice(openPorts),
		"discovery.open_udp_ports":    toAnySlice(openUDPPorts),
		"service.banner.tcp":          toAnySlice(banners),
		"service.http.details":        toAnySlice(httpDetails),
		"service.fingerprint.details": toAnySlice(fingerprints),
		"service.tech.tags":           toAnySlice(techTags),
		"service.smtp.details":        toAnySlice(smtpDetails),
		"service.ssh.details":         toAnySlice(sshDetails),
		"service.snmp.details":        toAnySlice(snmpDetails),
		"service.rpc.epmapper":        toAnySlice(rpcEpmapper),
		"service.rpc.details":         toAnySlice(rpcDetails),
		"service.rdp.details":         toAnySlice(rdpDetails),
		"service.tls.details":         toAnySlice(tlsDetails),
		"service.smb.details":         toAnySlice(smbDetails),
	}

	serviceIdentity, err := runDebugServiceIdentityStage(ctx, steps, pipelineInputs)
	if err != nil {
		return err
	}
	pipelineInputs["service.identity.details"] = toAnySlice(serviceIdentity)
	assetProfiles, err := runDebugAssetProfileStage(ctx, steps, pipelineInputs)
	if err != nil {
		return err
	}

	payload := scanDebugPayload{
		Target:          target,
		ResolvedTargets: resolved,
		OpenPorts:       openPorts,
		OpenUDPPorts:    openUDPPorts,
		Banners:         banners,
		HTTPDetails:     httpDetails,
		Fingerprints:    fingerprints,
		TechTags:        techTags,
		SMTPDetails:     smtpDetails,
		SSHDetails:      sshDetails,
		SNMPDetails:     snmpDetails,
		RPCEpmapper:     rpcEpmapper,
		RPCDetails:      rpcDetails,
		RDPDetails:      rdpDetails,
		TLSDetails:      tlsDetails,
		SMBDetails:      smbDetails,
		AssetProfiles:   assetProfiles,
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

//nolint:dupl // TCP and UDP debug discovery stages intentionally share the same orchestration shape.
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

//nolint:dupl // TCP and UDP debug discovery stages intentionally share the same orchestration shape.
func runDebugUDPPortDiscoveryStage(
	ctx context.Context,
	target string,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
) ([]discovery.UDPPortDiscoveryResult, error) {
	udpCfg := map[string]any{}
	if strings.TrimSpace(opts.UDPPorts) != "" {
		udpCfg["ports"] = splitAndTrim(opts.UDPPorts)
	}
	if opts.Timeout != "" {
		udpCfg["timeout"] = opts.Timeout
	}

	udpModule, err := engine.GetModuleInstance("scan_debug_udp_port_discovery", "udp-port-discovery", udpCfg)
	if err != nil {
		return nil, fmt.Errorf("create udp-port-discovery module: %w", err)
	}

	udpOutputs, udpExecErr := executeDebugModule(ctx, udpModule, map[string]any{
		"config.targets": []string{target},
	})
	if udpExecErr != nil {
		steps.addError("udp-port-discovery", udpExecErr.Error())
	}
	steps.addErrors("udp-port-discovery", collectOutputErrors(udpOutputs))
	openPorts := collectUDPDiscoveryResults(udpOutputs)
	if len(openPorts) == 0 {
		steps.addWarning("udp-port-discovery", "no open udp ports found")
	}
	return openPorts, nil
}

func runDebugBannerGrabStageWithModule(
	ctx context.Context,
	target string,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	openPorts []discovery.TCPPortDiscoveryResult,
	instanceID string,
	moduleType string,
	stepName string,
) ([]scanpkg.BannerGrabResult, error) {
	bannerCfg := map[string]any{}
	if opts.Timeout != "" {
		bannerCfg["read_timeout"] = opts.Timeout
		bannerCfg["connect_timeout"] = opts.Timeout
	}

	bannerModule, err := engine.GetModuleInstance(instanceID, moduleType, bannerCfg)
	if err != nil {
		return nil, fmt.Errorf("create %s module: %w", moduleType, err)
	}

	bannerInputs := map[string]any{
		"discovery.open_tcp_ports":    toAnySlice(openPorts),
		"config.original_cli_targets": []string{target},
	}
	bannerOutputs, bannerExecErr := executeDebugModule(ctx, bannerModule, bannerInputs)
	if bannerExecErr != nil {
		steps.addError(stepName, bannerExecErr.Error())
	}
	steps.addErrors(stepName, collectOutputErrors(bannerOutputs))
	banners := collectBannerResults(bannerOutputs)
	if len(banners) == 0 {
		steps.addWarning(stepName, "no banners captured")
	}
	steps.addWarnings(stepName, bannerWarnings(banners))
	return banners, nil
}

func runDebugRPCEpmapperStageWithModule(
	ctx context.Context,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	openPorts []discovery.TCPPortDiscoveryResult,
	instanceID string,
	moduleType string,
	stepName string,
) ([]scanpkg.RPCEpmapperInfo, error) {
	rpcConfig := map[string]any{}
	if opts.Timeout != "" {
		rpcConfig["timeout"] = opts.Timeout
		rpcConfig["connect_timeout"] = opts.Timeout
		rpcConfig["io_timeout"] = opts.Timeout
	}

	rpcModule, err := engine.GetModuleInstance(instanceID, moduleType, rpcConfig)
	if err != nil {
		return nil, fmt.Errorf("create %s module: %w", moduleType, err)
	}

	rpcOutputs, rpcExecErr := executeDebugModule(ctx, rpcModule, map[string]any{
		"discovery.open_tcp_ports": toAnySlice(openPorts),
	})
	if rpcExecErr != nil {
		steps.addError(stepName, rpcExecErr.Error())
	}
	steps.addErrors(stepName, collectOutputErrors(rpcOutputs))
	results := collectRPCEpmapperResults(rpcOutputs)
	if len(results) == 0 {
		steps.addWarning(stepName, "no rpc epmapper metadata generated")
	}
	return results, nil
}

//nolint:dupl // SMTP and SSH debug native stages intentionally share the same orchestration shape.
func runDebugSMTPNativeProbeStageWithModule(
	ctx context.Context,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	openPorts []discovery.TCPPortDiscoveryResult,
	banners []scanpkg.BannerGrabResult,
	instanceID string,
	moduleType string,
	stepName string,
) ([]scanpkg.SMTPServiceInfo, error) {
	smtpConfig := map[string]any{}
	if opts.Timeout != "" {
		smtpConfig["timeout"] = opts.Timeout
		smtpConfig["connect_timeout"] = opts.Timeout
		smtpConfig["io_timeout"] = opts.Timeout
		smtpConfig["retries"] = 0
	}

	smtpModule, err := engine.GetModuleInstance(instanceID, moduleType, smtpConfig)
	if err != nil {
		return nil, fmt.Errorf("create %s module: %w", moduleType, err)
	}

	smtpOutputs, smtpExecErr := executeDebugModule(ctx, smtpModule, map[string]any{
		"discovery.open_tcp_ports": toAnySlice(openPorts),
		"service.banner.tcp":       toAnySlice(banners),
	})
	if smtpExecErr != nil {
		steps.addError(stepName, smtpExecErr.Error())
	}
	steps.addErrors(stepName, collectOutputErrors(smtpOutputs))
	results := collectSMTPDetailsResults(smtpOutputs)
	if len(results) == 0 {
		if reason := debugSMTPCandidateWarning(openPorts, banners); reason != "" {
			steps.addWarning(stepName, reason)
		} else {
			steps.addWarning(stepName, "no smtp metadata generated")
		}
	}
	return results, nil
}

//nolint:dupl // SMTP and SSH debug native stages intentionally share the same orchestration shape.
func runDebugSSHNativeProbeStageWithModule(
	ctx context.Context,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	openPorts []discovery.TCPPortDiscoveryResult,
	banners []scanpkg.BannerGrabResult,
	instanceID string,
	moduleType string,
	stepName string,
) ([]scanpkg.SSHServiceInfo, error) {
	sshConfig := map[string]any{}
	if opts.Timeout != "" {
		sshConfig["timeout"] = opts.Timeout
		sshConfig["connect_timeout"] = opts.Timeout
		sshConfig["io_timeout"] = opts.Timeout
		sshConfig["retries"] = 0
	}

	sshModule, err := engine.GetModuleInstance(instanceID, moduleType, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("create %s module: %w", moduleType, err)
	}

	sshOutputs, sshExecErr := executeDebugModule(ctx, sshModule, map[string]any{
		"discovery.open_tcp_ports": toAnySlice(openPorts),
		"service.banner.tcp":       toAnySlice(banners),
	})
	if sshExecErr != nil {
		steps.addError(stepName, sshExecErr.Error())
	}
	steps.addErrors(stepName, collectOutputErrors(sshOutputs))
	results := collectSSHDetailsResults(sshOutputs)
	if len(results) == 0 {
		if reason := debugSSHCandidateWarning(openPorts, banners); reason != "" {
			steps.addWarning(stepName, reason)
		} else {
			steps.addWarning(stepName, "no ssh metadata generated")
		}
	}
	return results, nil
}

func runDebugSNMPNativeProbeStageWithModule(
	ctx context.Context,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	openPorts []discovery.UDPPortDiscoveryResult,
	instanceID string,
	moduleType string,
	stepName string,
) ([]scanpkg.SNMPServiceInfo, error) {
	snmpConfig := map[string]any{}
	if opts.Timeout != "" {
		snmpConfig["timeout"] = opts.Timeout
		snmpConfig["per_attempt_timeout"] = opts.Timeout
		snmpConfig["retries"] = 0
	}

	snmpModule, err := engine.GetModuleInstance(instanceID, moduleType, snmpConfig)
	if err != nil {
		return nil, fmt.Errorf("create %s module: %w", moduleType, err)
	}

	snmpOutputs, snmpExecErr := executeDebugModule(ctx, snmpModule, map[string]any{
		"discovery.open_udp_ports": toAnySlice(openPorts),
	})
	if snmpExecErr != nil {
		steps.addError(stepName, snmpExecErr.Error())
	}
	steps.addErrors(stepName, collectOutputErrors(snmpOutputs))
	results := collectSNMPDetailsResults(snmpOutputs)
	if len(results) == 0 {
		if reason := debugSNMPCandidateWarning(openPorts); reason != "" {
			steps.addWarning(stepName, reason)
		} else {
			steps.addWarning(stepName, "no snmp metadata generated")
		}
	}
	return results, nil
}

func runDebugRPCFollowupStageWithModule(
	ctx context.Context,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	rpcEpmapper []scanpkg.RPCEpmapperInfo,
	instanceID string,
	moduleType string,
	stepName string,
) ([]scanpkg.RPCServiceInfo, error) {
	rpcConfig := map[string]any{}
	if opts.Timeout != "" {
		rpcConfig["host_total_timeout"] = opts.Timeout
		rpcConfig["per_port_total_timeout"] = opts.Timeout
		rpcConfig["connect_timeout"] = opts.Timeout
		rpcConfig["io_timeout"] = opts.Timeout
	}

	rpcModule, err := engine.GetModuleInstance(instanceID, moduleType, rpcConfig)
	if err != nil {
		return nil, fmt.Errorf("create %s module: %w", moduleType, err)
	}

	consumeKey := "service.rpc.epmapper"
	if consumes := rpcModule.Metadata().Consumes; len(consumes) > 0 && strings.TrimSpace(consumes[0].Key) != "" {
		consumeKey = consumes[0].Key
	}
	rpcOutputs, rpcExecErr := executeDebugModule(ctx, rpcModule, map[string]any{
		consumeKey: toAnySlice(rpcEpmapper),
	})
	if rpcExecErr != nil {
		steps.addError(stepName, rpcExecErr.Error())
	}
	steps.addErrors(stepName, collectOutputErrors(rpcOutputs))
	results := collectRPCDetailsResults(rpcOutputs)
	if len(results) == 0 {
		steps.addWarning(stepName, "no rpc follow-up metadata generated")
	}
	return results, nil
}

//nolint:dupl // HTTP and fingerprint parser stages intentionally share the same orchestration shape.
func runDebugHTTPStageWithModule(
	ctx context.Context,
	steps *scanDebugStepCollection,
	banners []scanpkg.BannerGrabResult,
	instanceID string,
	moduleType string,
	stepName string,
) ([]parsepkg.HTTPParsedInfo, error) {
	httpModule, err := engine.GetModuleInstance(instanceID, moduleType, map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("create %s module: %w", moduleType, err)
	}

	inputKey := "service.banner.tcp"
	if consumes := httpModule.Metadata().Consumes; len(consumes) > 0 && strings.TrimSpace(consumes[0].Key) != "" {
		inputKey = consumes[0].Key
	}
	httpOutputs, httpExecErr := executeDebugModule(ctx, httpModule, map[string]any{
		inputKey: toAnySlice(banners),
	})
	if httpExecErr != nil {
		steps.addError(stepName, httpExecErr.Error())
	}
	steps.addErrors(stepName, collectOutputErrors(httpOutputs))
	httpDetails := collectHTTPDetailsResults(httpOutputs)
	if len(httpDetails) == 0 {
		steps.addWarning(stepName, "no http details generated")
	}
	return httpDetails, nil
}

//nolint:dupl // HTTP and fingerprint parser stages intentionally share the same orchestration shape.
func runDebugFingerprintStageWithModule(
	ctx context.Context,
	steps *scanDebugStepCollection,
	banners []scanpkg.BannerGrabResult,
	instanceID string,
	moduleType string,
	stepName string,
) ([]parsepkg.FingerprintParsedInfo, error) {
	fingerprintModule, err := engine.GetModuleInstance(instanceID, moduleType, map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("create %s module: %w", moduleType, err)
	}

	inputKey := "service.banner.tcp"
	if consumes := fingerprintModule.Metadata().Consumes; len(consumes) > 0 && strings.TrimSpace(consumes[0].Key) != "" {
		inputKey = consumes[0].Key
	}
	fingerprintOutputs, fingerprintExecErr := executeDebugModule(ctx, fingerprintModule, map[string]any{
		inputKey: toAnySlice(banners),
	})
	if fingerprintExecErr != nil {
		steps.addError(stepName, fingerprintExecErr.Error())
	}
	steps.addErrors(stepName, collectOutputErrors(fingerprintOutputs))
	fingerprints := collectFingerprintResults(fingerprintOutputs)
	if len(fingerprints) == 0 {
		steps.addWarning(stepName, "no fingerprint matches")
	}
	return fingerprints, nil
}

func runDebugTechTagStageWithModule(
	ctx context.Context,
	steps *scanDebugStepCollection,
	banners []scanpkg.BannerGrabResult,
	httpDetails []parsepkg.HTTPParsedInfo,
	fingerprints []parsepkg.FingerprintParsedInfo,
	instanceID string,
	moduleType string,
	stepName string,
) ([]parsepkg.TechTagResult, error) {
	techModule, err := engine.GetModuleInstance(instanceID, moduleType, map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("create %s module: %w", moduleType, err)
	}

	inputs := map[string]any{}
	if consumes := techModule.Metadata().Consumes; len(consumes) >= 3 {
		inputs[consumes[0].Key] = toAnySlice(fingerprints)
		inputs[consumes[1].Key] = toAnySlice(httpDetails)
		inputs[consumes[2].Key] = toAnySlice(banners)
	} else {
		inputs["service.banner.tcp"] = toAnySlice(banners)
		inputs["service.http.details"] = toAnySlice(httpDetails)
		inputs["service.fingerprint.details"] = toAnySlice(fingerprints)
	}
	techOutputs, techExecErr := executeDebugModule(ctx, techModule, inputs)
	if techExecErr != nil {
		steps.addError(stepName, techExecErr.Error())
	}
	steps.addErrors(stepName, collectOutputErrors(techOutputs))
	techTags := collectTechTagResults(techOutputs)
	if len(techTags) == 0 {
		steps.addWarning(stepName, "no tech tags generated")
	}
	return techTags, nil
}

//nolint:dupl // SMB and RDP debug native stages intentionally share the same orchestration shape.
func runDebugSMBNativeProbeStageWithModule(
	ctx context.Context,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	openPorts []discovery.TCPPortDiscoveryResult,
	banners []scanpkg.BannerGrabResult,
	instanceID string,
	moduleType string,
	stepName string,
) ([]scanpkg.SMBServiceInfo, error) {
	smbConfig := map[string]any{}
	if opts.Timeout != "" {
		smbConfig["timeout"] = opts.Timeout
		smbConfig["connect_timeout"] = opts.Timeout
		smbConfig["io_timeout"] = opts.Timeout
		smbConfig["retries"] = 1
	}

	smbModule, err := engine.GetModuleInstance(instanceID, moduleType, smbConfig)
	if err != nil {
		return nil, fmt.Errorf("create %s module: %w", moduleType, err)
	}

	smbOutputs, smbExecErr := executeDebugModule(ctx, smbModule, map[string]any{
		"discovery.open_tcp_ports": toAnySlice(openPorts),
		"service.banner.tcp":       toAnySlice(banners),
	})
	if smbExecErr != nil {
		steps.addError(stepName, smbExecErr.Error())
	}
	steps.addErrors(stepName, collectOutputErrors(smbOutputs))
	smbDetails := collectSMBDetailsResults(smbOutputs)
	if len(smbDetails) == 0 {
		steps.addWarning(stepName, "no smb metadata generated")
	}
	return smbDetails, nil
}

//nolint:dupl // SMB and RDP debug native stages intentionally share the same orchestration shape.
func runDebugRDPNativeProbeStageWithModule(
	ctx context.Context,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	openPorts []discovery.TCPPortDiscoveryResult,
	banners []scanpkg.BannerGrabResult,
	instanceID string,
	moduleType string,
	stepName string,
) ([]scanpkg.RDPServiceInfo, error) {
	rdpConfig := map[string]any{}
	if opts.Timeout != "" {
		rdpConfig["timeout"] = opts.Timeout
		rdpConfig["connect_timeout"] = opts.Timeout
		rdpConfig["io_timeout"] = opts.Timeout
		rdpConfig["retries"] = 0
	}

	rdpModule, err := engine.GetModuleInstance(instanceID, moduleType, rdpConfig)
	if err != nil {
		return nil, fmt.Errorf("create %s module: %w", moduleType, err)
	}

	rdpOutputs, rdpExecErr := executeDebugModule(ctx, rdpModule, map[string]any{
		"discovery.open_tcp_ports": toAnySlice(openPorts),
		"service.banner.tcp":       toAnySlice(banners),
	})
	if rdpExecErr != nil {
		steps.addError(stepName, rdpExecErr.Error())
	}
	steps.addErrors(stepName, collectOutputErrors(rdpOutputs))
	rdpDetails := collectRDPDetailsResults(rdpOutputs)
	if len(rdpDetails) == 0 {
		steps.addWarning(stepName, "no rdp metadata generated")
	}
	return rdpDetails, nil
}

func runDebugTLSNativeProbeStageWithModule(
	ctx context.Context,
	opts scanDebugTargetOptions,
	steps *scanDebugStepCollection,
	openPorts []discovery.TCPPortDiscoveryResult,
	banners []scanpkg.BannerGrabResult,
	instanceID string,
	moduleType string,
	stepName string,
) ([]scanpkg.TLSServiceInfo, error) {
	tlsConfig := map[string]any{}
	if opts.Timeout != "" {
		tlsConfig["timeout"] = opts.Timeout
		tlsConfig["connect_timeout"] = opts.Timeout
		tlsConfig["io_timeout"] = opts.Timeout
		tlsConfig["retries"] = 0
	}
	if extraPorts := debugTLSExtraPortsFromBanners(banners); len(extraPorts) > 0 {
		tlsConfig["extra_ports"] = extraPorts
	}

	tlsModule, err := engine.GetModuleInstance(instanceID, moduleType, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("create %s module: %w", moduleType, err)
	}

	tlsOutputs, tlsExecErr := executeDebugModule(ctx, tlsModule, map[string]any{
		"discovery.open_tcp_ports": toAnySlice(openPorts),
	})
	if tlsExecErr != nil {
		steps.addError(stepName, tlsExecErr.Error())
	}
	steps.addErrors(stepName, collectOutputErrors(tlsOutputs))
	tlsDetails := collectTLSDetailsResults(tlsOutputs)
	if len(tlsDetails) == 0 {
		if reason := debugTLSCandidateWarning(openPorts, banners); reason != "" {
			steps.addWarning(stepName, reason)
		} else {
			steps.addWarning(stepName, "no tls metadata generated")
		}
	}
	return tlsDetails, nil
}

func runDebugServiceIdentityStage(
	ctx context.Context,
	steps *scanDebugStepCollection,
	inputs map[string]any,
) ([]parsepkg.ServiceIdentityInfo, error) {
	normalizerModule, err := engine.GetModuleInstance("scan_debug_service_identity_normalizer", "service-identity-normalizer", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("create service-identity-normalizer module: %w", err)
	}

	normalizerOutputs, normalizerExecErr := executeDebugModule(ctx, normalizerModule, inputs)
	if normalizerExecErr != nil {
		steps.addError("service-identity-normalizer", normalizerExecErr.Error())
	}
	steps.addErrors("service-identity-normalizer", collectOutputErrors(normalizerOutputs))
	serviceIdentity := collectServiceIdentityResultsByDataKey(normalizerOutputs, "service.identity.details")
	if len(serviceIdentity) == 0 {
		steps.addWarning("service-identity-normalizer", "no canonical service identity generated")
	}
	return serviceIdentity, nil
}

func runDebugAssetProfileStage(
	ctx context.Context,
	steps *scanDebugStepCollection,
	inputs map[string]any,
) ([]engine.AssetProfile, error) {
	builderModule, err := engine.GetModuleInstance("scan_debug_asset_profile_builder", "asset-profile-builder", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("create asset-profile-builder module: %w", err)
	}

	builderOutputs, builderExecErr := executeDebugModule(ctx, builderModule, inputs)
	if builderExecErr != nil {
		steps.addError("asset-profile-builder", builderExecErr.Error())
	}
	steps.addErrors("asset-profile-builder", collectOutputErrors(builderOutputs))
	profiles := collectAssetProfilesResultsByDataKey(builderOutputs, "asset.profiles")
	if len(profiles) == 0 {
		steps.addWarning("asset-profile-builder", "no canonical asset profiles generated")
	}
	return profiles, nil
}

func debugSSHCandidateWarning(openPorts []discovery.TCPPortDiscoveryResult, banners []scanpkg.BannerGrabResult) string {
	if debugHasSSHCandidate(openPorts, banners) {
		return ""
	}
	if debugHasOpenPorts(openPorts) {
		return "non_family_port_without_banner_hint"
	}
	return "no_candidate"
}

func debugSMTPCandidateWarning(openPorts []discovery.TCPPortDiscoveryResult, banners []scanpkg.BannerGrabResult) string {
	if debugHasSMTPCandidate(openPorts, banners) {
		return ""
	}
	if debugHasOpenPorts(openPorts) {
		return "non_family_port_without_banner_hint"
	}
	return "no_candidate"
}

func debugTLSCandidateWarning(openPorts []discovery.TCPPortDiscoveryResult, banners []scanpkg.BannerGrabResult) string {
	if debugHasTLSCandidate(openPorts, banners) {
		return ""
	}
	if debugHasOpenPorts(openPorts) {
		return "non_family_port_without_banner_hint"
	}
	return "no_candidate"
}

func debugSNMPCandidateWarning(openPorts []discovery.UDPPortDiscoveryResult) string {
	if debugHasSNMPCandidate(openPorts) {
		return ""
	}
	if len(openPorts) > 0 {
		return "non_family_port_without_banner_hint"
	}
	return "no_candidate"
}

func debugHasOpenPorts(openPorts []discovery.TCPPortDiscoveryResult) bool {
	for _, result := range openPorts {
		if len(result.OpenPorts) > 0 {
			return true
		}
	}
	return false
}

func debugHasSSHCandidate(openPorts []discovery.TCPPortDiscoveryResult, banners []scanpkg.BannerGrabResult) bool {
	for _, result := range openPorts {
		if slices.Contains(result.OpenPorts, 22) {
			return true
		}
	}
	for _, banner := range banners {
		if banner.Port == 22 || debugBannerLooksLikeSSH(banner) {
			return true
		}
	}
	return false
}

func debugHasSMTPCandidate(openPorts []discovery.TCPPortDiscoveryResult, banners []scanpkg.BannerGrabResult) bool {
	for _, result := range openPorts {
		if slices.ContainsFunc(result.OpenPorts, debugIsSMTPPort) {
			return true
		}
	}
	for _, banner := range banners {
		if debugIsSMTPPort(banner.Port) || debugBannerLooksLikeSMTP(banner) {
			return true
		}
	}
	return false
}

func debugHasTLSCandidate(openPorts []discovery.TCPPortDiscoveryResult, banners []scanpkg.BannerGrabResult) bool {
	for _, result := range openPorts {
		if slices.ContainsFunc(result.OpenPorts, debugIsTLSPort) {
			return true
		}
	}
	return len(debugTLSExtraPortsFromBanners(banners)) > 0
}

func debugHasSNMPCandidate(openPorts []discovery.UDPPortDiscoveryResult) bool {
	for _, result := range openPorts {
		if slices.Contains(result.OpenPorts, 161) {
			return true
		}
	}
	return false
}

func debugTLSExtraPortsFromBanners(banners []scanpkg.BannerGrabResult) []int {
	seen := map[int]struct{}{}
	ports := make([]int, 0)
	for _, banner := range banners {
		if banner.Port <= 0 || debugIsTLSPort(banner.Port) {
			continue
		}
		if !debugBannerLooksLikeTLS(banner) {
			continue
		}
		if _, ok := seen[banner.Port]; ok {
			continue
		}
		seen[banner.Port] = struct{}{}
		ports = append(ports, banner.Port)
	}
	sort.Ints(ports)
	return ports
}

func debugIsSMTPPort(port int) bool {
	switch port {
	case 25, 465, 587, 2525:
		return true
	default:
		return false
	}
}

func debugIsTLSPort(port int) bool {
	switch port {
	case 443, 8443, 9443:
		return true
	default:
		return false
	}
}

func debugBannerLooksLikeSSH(banner scanpkg.BannerGrabResult) bool {
	return debugContainsAnyHint(banner.Protocol, "ssh") ||
		debugContainsAnyHint(banner.Banner, "ssh") ||
		debugEvidenceLooksLike(banner.Evidence, []string{"ssh"})
}

func debugBannerLooksLikeSMTP(banner scanpkg.BannerGrabResult) bool {
	return debugContainsAnyHint(banner.Protocol, "smtp", "esmtp", "submission") ||
		debugContainsAnyHint(banner.Banner, "smtp", "esmtp", "submission") ||
		debugEvidenceLooksLike(banner.Evidence, []string{"smtp", "esmtp", "submission"})
}

func debugBannerLooksLikeTLS(banner scanpkg.BannerGrabResult) bool {
	if banner.IsTLS {
		return true
	}
	if debugContainsAnyHint(banner.Protocol, "https", "tls", "ssl") || debugContainsAnyHint(banner.Banner, "http/", "https", "tls", "ssl", "starttls", "smtps") {
		return true
	}
	return debugEvidenceLooksLike(banner.Evidence, []string{"https", "tls", "ssl", "starttls", "smtps", "http/"})
}

func debugContainsAnyHint(value string, hints ...string) bool {
	clean := strings.ToLower(strings.TrimSpace(value))
	if clean == "" {
		return false
	}
	for _, hint := range hints {
		if strings.Contains(clean, hint) {
			return true
		}
	}
	return false
}

func debugEvidenceLooksLike(evidence []engine.ProbeObservation, hints []string) bool {
	for _, obs := range evidence {
		for _, value := range []string{obs.Protocol, obs.ProbeID, obs.Description, obs.Response} {
			if debugContainsAnyHint(value, hints...) {
				return true
			}
		}
	}
	return false
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

func collectUDPDiscoveryResults(outputs []engine.ModuleOutput) []discovery.UDPPortDiscoveryResult {
	results := make([]discovery.UDPPortDiscoveryResult, 0)
	for _, output := range outputs {
		switch data := output.Data.(type) {
		case discovery.UDPPortDiscoveryResult:
			results = append(results, data)
		case []discovery.UDPPortDiscoveryResult:
			results = append(results, data...)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Target < results[j].Target
	})
	return results
}

func collectHTTPDetailsResults(outputs []engine.ModuleOutput) []parsepkg.HTTPParsedInfo {
	results := make([]parsepkg.HTTPParsedInfo, 0)
	for _, output := range outputs {
		switch data := output.Data.(type) {
		case parsepkg.HTTPParsedInfo:
			results = append(results, data)
		case []parsepkg.HTTPParsedInfo:
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

func collectSNMPDetailsResults(outputs []engine.ModuleOutput) []scanpkg.SNMPServiceInfo {
	results := make([]scanpkg.SNMPServiceInfo, 0)
	for _, output := range outputs {
		switch data := output.Data.(type) {
		case scanpkg.SNMPServiceInfo:
			results = append(results, data)
		case []scanpkg.SNMPServiceInfo:
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

func collectServiceIdentityResultsByDataKey(outputs []engine.ModuleOutput, dataKey string) []parsepkg.ServiceIdentityInfo {
	filtered := make([]engine.ModuleOutput, 0, len(outputs))
	for _, output := range outputs {
		if output.DataKey == dataKey {
			filtered = append(filtered, output)
		}
	}
	return collectServiceIdentityResults(filtered)
}

func collectAssetProfilesResultsByDataKey(outputs []engine.ModuleOutput, dataKey string) []engine.AssetProfile {
	for _, output := range outputs {
		if output.DataKey != dataKey {
			continue
		}
		switch data := output.Data.(type) {
		case []engine.AssetProfile:
			return data
		case []any:
			results := make([]engine.AssetProfile, 0, len(data))
			for _, item := range data {
				if profile, ok := item.(engine.AssetProfile); ok {
					results = append(results, profile)
				}
			}
			return results
		}
	}
	return nil
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
	fmt.Fprintf(w, "Open UDP Port Entries: %d\n", len(payload.OpenUDPPorts))
	fmt.Fprintf(w, "Banners: %d\n", len(payload.Banners))
	fmt.Fprintf(w, "Fingerprints: %d\n", len(payload.Fingerprints))
	fmt.Fprintf(w, "Tech Tags: %d\n", len(payload.TechTags))
	fmt.Fprintf(w, "SMTP Details: %d\n", len(payload.SMTPDetails))
	fmt.Fprintf(w, "SSH Details: %d\n", len(payload.SSHDetails))
	fmt.Fprintf(w, "SNMP Details: %d\n", len(payload.SNMPDetails))
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
