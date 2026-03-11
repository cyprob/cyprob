package engine

import (
	"context"
	"testing"
)

// helper to register a minimal fake module with given meta
func fakeFactory(meta ModuleMetadata) ModuleFactory {
	return func() Module {
		return &fakeModule{meta: meta}
	}
}

type fakeModule struct{ meta ModuleMetadata }

type fakeConfigManager struct {
	values map[string]any
}

func (f *fakeConfigManager) GetValue(key string) any {
	if f == nil {
		return nil
	}
	return f.values[key]
}

func (f *fakeModule) Metadata() ModuleMetadata          { return f.meta }
func (f *fakeModule) Init(string, map[string]any) error { return nil }
func (f *fakeModule) Execute(_ context.Context, _ map[string]any, _ chan<- ModuleOutput) error {
	return nil
}

// Test PlanDAG basic path with default intent and module selection
func TestPlanner_PlanDAG_DefaultProfile_SelectsAndConfigures(t *testing.T) {
	// discovery depends on targets only (implicit), scan consumes discovery output, reporter no deps
	discoveryMeta := ModuleMetadata{
		Name: "tcp-port-discovery", Type: DiscoveryModuleType,
		Consumes:     nil,
		Produces:     []DataContractEntry{{Key: "discovery.open_tcp_ports"}},
		ConfigSchema: map[string]ParameterDefinition{"timeout": {Default: "1s"}},
	}
	scanMeta := ModuleMetadata{
		Name: "banner-grabber", Type: ScanModuleType,
		Consumes: []DataContractEntry{{Key: "discovery.open_tcp_ports"}},
		Produces: []DataContractEntry{{Key: "service.banner.tcp"}},
		ConfigSchema: map[string]ParameterDefinition{
			"read_timeout":    {Default: "3s"},
			"connect_timeout": {Default: "2s"},
		},
		Tags: []string{"scan"},
	}
	parseMeta := ModuleMetadata{
		Name: "http-parser", Type: ParseModuleType,
		Consumes:     []DataContractEntry{{Key: "service.banner.tcp", IsOptional: true}},
		Produces:     []DataContractEntry{{Key: "service.http.details"}},
		ConfigSchema: map[string]ParameterDefinition{},
		Tags:         []string{"parse"},
	}
	reporterMeta := ModuleMetadata{
		Name: "json-reporter", Type: ReportingModuleType,
		ConfigSchema: map[string]ParameterDefinition{},
		Tags:         []string{"report"},
	}

	registry := map[string]ModuleFactory{
		discoveryMeta.Name: fakeFactory(discoveryMeta),
		scanMeta.Name:      fakeFactory(scanMeta),
		parseMeta.Name:     fakeFactory(parseMeta),
		reporterMeta.Name:  fakeFactory(reporterMeta),
	}

	planner, err := NewDAGPlanner(registry, nil)
	if err != nil {
		t.Fatalf("NewDAGPlanner error: %v", err)
	}

	intent := ScanIntent{Targets: []string{"127.0.0.1"}, CustomTimeout: "10s"}
	dag, err := planner.PlanDAG(intent)
	if err != nil {
		t.Fatalf("PlanDAG error: %v", err)
	}
	if dag == nil || len(dag.Nodes) == 0 {
		t.Fatalf("expected nodes in DAG, got %+v", dag)
	}

	// Verify unique instance IDs and configs applied
	names := map[string]bool{}
	hasDiscovery, hasScan, hasParse, hasReporter := false, false, false, false
	var scanCfg map[string]any
	for _, n := range dag.Nodes {
		if names[n.InstanceID] {
			t.Fatalf("duplicate instance id: %s", n.InstanceID)
		}
		names[n.InstanceID] = true
		switch n.ModuleType {
		case discoveryMeta.Name:
			hasDiscovery = true
		case scanMeta.Name:
			hasScan = true
			scanCfg = n.Config
		case parseMeta.Name:
			hasParse = true
		case reporterMeta.Name:
			hasReporter = true
		}
	}
	if !hasDiscovery || !hasScan || !hasParse || !hasReporter {
		t.Fatalf("expected discovery, scan, parse, reporter: got D=%v S=%v P=%v R=%v", hasDiscovery, hasScan, hasParse, hasReporter)
	}
	// From planner change: when CustomTimeout set, banner-grabber gets read/connect timeouts
	if scanCfg == nil {
		t.Fatalf("scan node config missing")
	}
	if scanCfg["read_timeout"] != "10s" || scanCfg["connect_timeout"] != "10s" {
		t.Fatalf("expected scan timeouts to be 10s, got read=%v connect=%v", scanCfg["read_timeout"], scanCfg["connect_timeout"])
	}
}

func TestPlanner_configureModule_AppliesCustoms(t *testing.T) {
	planner, _ := NewDAGPlanner(nil, nil)
	// tcp-port-discovery gets ports and timeout from intent
	meta := ModuleMetadata{Name: "tcp-port-discovery", ConfigSchema: map[string]ParameterDefinition{"ports": {Default: nil}, "timeout": {Default: nil}}}
	cfg := planner.configureModule(meta, ScanIntent{CustomPortConfig: "80,443", CustomTimeout: "5s"})
	if cfg["timeout"] != "5s" {
		t.Fatalf("expected discovery timeout 5s, got %v", cfg["timeout"])
	}

	// banner-grabber gets propagated timeouts
	scanMeta := ModuleMetadata{Name: "banner-grabber", ConfigSchema: map[string]ParameterDefinition{"read_timeout": {Default: "3s"}, "connect_timeout": {Default: "2s"}}}
	sc := planner.configureModule(scanMeta, ScanIntent{CustomTimeout: "7s"})
	if sc["read_timeout"] != "7s" || sc["connect_timeout"] != "7s" {
		t.Fatalf("expected scan timeouts 7s, got read=%v connect=%v", sc["read_timeout"], sc["connect_timeout"])
	}
}

func TestPlanner_generateInstanceID_Unique(t *testing.T) {
	planner, _ := NewDAGPlanner(nil, nil)
	existing := map[string]DAGNodeConfig{"banner_grabber": {InstanceID: "banner_grabber"}}
	id := planner.generateInstanceID("banner-grabber", existing)
	if id == "banner_grabber" {
		t.Fatalf("expected unique id not equal to existing, got %s", id)
	}
}

// Test filterHostDiscoveryModules filters ICMP but preserves port scanners
func TestPlanner_filterHostDiscoveryModules(t *testing.T) {
	planner, _ := NewDAGPlanner(nil, nil)

	icmpMeta := ModuleMetadata{Name: "icmp-ping-discovery", Type: DiscoveryModuleType}
	tcpPortMeta := ModuleMetadata{Name: "tcp-port-discovery", Type: DiscoveryModuleType}
	udpPortMeta := ModuleMetadata{Name: "udp-port-discovery", Type: DiscoveryModuleType}
	scanMeta := ModuleMetadata{Name: "banner-grabber", Type: ScanModuleType}

	factories := []ModuleFactory{
		fakeFactory(icmpMeta),
		fakeFactory(tcpPortMeta),
		fakeFactory(udpPortMeta),
		fakeFactory(scanMeta),
	}

	filtered := planner.filterHostDiscoveryModules(factories)

	// Should have 3 modules: tcp-port-discovery, udp-port-discovery, banner-grabber
	// ICMP should be filtered out
	if len(filtered) != 3 {
		t.Fatalf("expected 3 modules after filtering, got %d", len(filtered))
	}

	hasICMP, hasTCPPort, hasUDPPort, hasScan := false, false, false, false
	for _, factory := range filtered {
		meta := factory().Metadata()
		switch meta.Name {
		case "icmp-ping-discovery":
			hasICMP = true
		case "tcp-port-discovery":
			hasTCPPort = true
		case "udp-port-discovery":
			hasUDPPort = true
		case "banner-grabber":
			hasScan = true
		}
	}

	if hasICMP {
		t.Fatal("ICMP ping should be filtered out")
	}
	if !hasTCPPort {
		t.Fatal("TCP port discovery should be preserved")
	}
	if !hasUDPPort {
		t.Fatal("UDP port discovery should be preserved")
	}
	if !hasScan {
		t.Fatal("Scanner module should be preserved")
	}
}

// Test selectModulesByProfile with SkipDiscovery
func TestPlanner_selectModulesByProfile_SkipDiscovery(t *testing.T) {
	icmpMeta := ModuleMetadata{Name: "icmp-ping-discovery", Type: DiscoveryModuleType}
	tcpPortMeta := ModuleMetadata{Name: "tcp-port-discovery", Type: DiscoveryModuleType}
	scanMeta := ModuleMetadata{Name: "banner-grabber", Type: ScanModuleType}
	parseMeta := ModuleMetadata{Name: "http-parser", Type: ParseModuleType}

	registry := map[string]ModuleFactory{
		icmpMeta.Name:    fakeFactory(icmpMeta),
		tcpPortMeta.Name: fakeFactory(tcpPortMeta),
		scanMeta.Name:    fakeFactory(scanMeta),
		parseMeta.Name:   fakeFactory(parseMeta),
	}

	planner, _ := NewDAGPlanner(registry, nil)

	// Test with SkipDiscovery=false (normal)
	intent := ScanIntent{Targets: []string{"127.0.0.1"}, SkipDiscovery: false}
	selected := planner.selectModulesForIntent(intent)

	// Should include tcp-port-discovery and parse modules
	hasTCPPort := false
	for _, factory := range selected {
		if factory().Metadata().Name == "tcp-port-discovery" {
			hasTCPPort = true
			break
		}
	}
	if !hasTCPPort {
		t.Fatal("expected tcp-port-discovery when SkipDiscovery=false")
	}

	// Test with SkipDiscovery=true
	intentSkip := ScanIntent{Targets: []string{"127.0.0.1"}, SkipDiscovery: true}
	selectedSkip := planner.selectModulesForIntent(intentSkip)

	// Should still include tcp-port-discovery (port scanner, not host discovery)
	hasTCPPortSkip := false
	hasICMP := false
	for _, factory := range selectedSkip {
		meta := factory().Metadata()
		if meta.Name == "tcp-port-discovery" {
			hasTCPPortSkip = true
		}
		if meta.Name == "icmp-ping-discovery" {
			hasICMP = true
		}
	}

	if !hasTCPPortSkip {
		t.Fatal("tcp-port-discovery should be preserved with SkipDiscovery=true")
	}
	if hasICMP {
		t.Fatal("ICMP should be filtered out with SkipDiscovery=true")
	}
}

// Test initializeDataKeys keeps only explicit initial inputs.
func TestPlanner_initializeDataKeys_SkipDiscovery(t *testing.T) {
	planner, _ := NewDAGPlanner(nil, nil)

	// Without SkipDiscovery
	intent := ScanIntent{Targets: []string{"127.0.0.1"}, SkipDiscovery: false}
	keys := planner.initializeDataKeys(intent)

	if _, found := keys["config.targets"]; !found {
		t.Fatal("expected config.targets to be initialized")
	}
	if _, found := keys["discovery.live_hosts"]; found {
		t.Fatal("discovery.live_hosts should NOT be initialized when SkipDiscovery=false")
	}

	// With SkipDiscovery
	intentSkip := ScanIntent{Targets: []string{"127.0.0.1"}, SkipDiscovery: true}
	keysSkip := planner.initializeDataKeys(intentSkip)

	if _, found := keysSkip["config.targets"]; !found {
		t.Fatal("expected config.targets to be initialized")
	}
	if _, found := keysSkip["discovery.live_hosts"]; found {
		t.Fatal("discovery.live_hosts should not be initialized when SkipDiscovery=true")
	}
}

func TestPlanner_selectModulesByProfile_PingDisabled(t *testing.T) {
	icmpMeta := ModuleMetadata{Name: "icmp-ping-discovery", Type: DiscoveryModuleType}
	tcpPortMeta := ModuleMetadata{Name: "tcp-port-discovery", Type: DiscoveryModuleType}
	udpPortMeta := ModuleMetadata{Name: "udp-port-discovery", Type: DiscoveryModuleType}

	registry := map[string]ModuleFactory{
		icmpMeta.Name:    fakeFactory(icmpMeta),
		tcpPortMeta.Name: fakeFactory(tcpPortMeta),
		udpPortMeta.Name: fakeFactory(udpPortMeta),
	}

	planner, _ := NewDAGPlanner(registry, nil)
	selected := planner.selectModulesForIntent(ScanIntent{
		Targets:    []string{"127.0.0.1"},
		EnablePing: false,
	})

	hasICMP := false
	hasTCP := false
	hasUDP := false
	for _, factory := range selected {
		switch factory().Metadata().Name {
		case "icmp-ping-discovery":
			hasICMP = true
		case "tcp-port-discovery":
			hasTCP = true
		case "udp-port-discovery":
			hasUDP = true
		}
	}

	if hasICMP {
		t.Fatal("icmp-ping-discovery should be filtered when EnablePing=false")
	}
	if !hasTCP {
		t.Fatal("tcp-port-discovery should remain when EnablePing=false")
	}
	if !hasUDP {
		t.Fatal("udp-port-discovery should remain when EnablePing=false")
	}
}

// Test different profiles select correct modules
func TestPlanner_selectModulesByProfile_Profiles(t *testing.T) {
	discoveryMeta := ModuleMetadata{Name: "icmp-ping", Type: DiscoveryModuleType}
	scanMeta := ModuleMetadata{Name: "scanner", Type: ScanModuleType, Tags: []string{"quick"}}
	evalMeta := ModuleMetadata{Name: "evaluator", Type: EvaluationModuleType}

	registry := map[string]ModuleFactory{
		discoveryMeta.Name: fakeFactory(discoveryMeta),
		scanMeta.Name:      fakeFactory(scanMeta),
		evalMeta.Name:      fakeFactory(evalMeta),
	}

	planner, _ := NewDAGPlanner(registry, nil)

	// Test DiscoveryOnly
	intentDiscovery := ScanIntent{DiscoveryOnly: true}
	selected := planner.selectModulesByProfile(intentDiscovery)
	hasDiscovery := false
	for _, factory := range selected {
		if factory().Metadata().Type == DiscoveryModuleType {
			hasDiscovery = true
		}
	}
	if !hasDiscovery {
		t.Fatal("DiscoveryOnly should select discovery modules")
	}

	// Test quick_discovery profile
	intentQuick := ScanIntent{Profile: "quick_discovery"}
	selectedQuick := planner.selectModulesByProfile(intentQuick)
	if len(selectedQuick) == 0 {
		t.Fatal("quick_discovery should select modules")
	}

	// Test full_scan with EnableVulnChecks
	intentFull := ScanIntent{Profile: "full_scan", EnableVulnChecks: true}
	selectedFull := planner.selectModulesByProfile(intentFull)
	hasEval := false
	for _, factory := range selectedFull {
		if factory().Metadata().Type == EvaluationModuleType {
			hasEval = true
		}
	}
	if !hasEval {
		t.Fatal("full_scan with EnableVulnChecks should include evaluation modules")
	}
}

// Test matchesTags covers all scenarios
func TestPlanner_matchesTags(t *testing.T) {
	planner, _ := NewDAGPlanner(nil, nil)

	tests := []struct {
		name        string
		moduleTags  []string
		includeTags []string
		excludeTags []string
		want        bool
	}{
		{
			name:        "no filters - should match",
			moduleTags:  []string{"tag1", "tag2"},
			includeTags: nil,
			excludeTags: nil,
			want:        true,
		},
		{
			name:        "exclude tag present - should not match",
			moduleTags:  []string{"tag1", "intrusive"},
			includeTags: nil,
			excludeTags: []string{"intrusive"},
			want:        false,
		},
		{
			name:        "exclude tag not present - should match",
			moduleTags:  []string{"tag1", "tag2"},
			includeTags: nil,
			excludeTags: []string{"intrusive"},
			want:        true,
		},
		{
			name:        "include tag present - should match",
			moduleTags:  []string{"tag1", "quick"},
			includeTags: []string{"quick"},
			excludeTags: nil,
			want:        true,
		},
		{
			name:        "include tag not present - should not match",
			moduleTags:  []string{"tag1", "tag2"},
			includeTags: []string{"quick"},
			excludeTags: nil,
			want:        false,
		},
		{
			name:        "both include and exclude, include present - should match",
			moduleTags:  []string{"tag1", "quick"},
			includeTags: []string{"quick"},
			excludeTags: []string{"intrusive"},
			want:        true,
		},
		{
			name:        "both include and exclude, exclude present - should not match",
			moduleTags:  []string{"tag1", "quick", "intrusive"},
			includeTags: []string{"quick"},
			excludeTags: []string{"intrusive"},
			want:        false,
		},
		{
			name:        "multiple include tags, one matches - should match",
			moduleTags:  []string{"tag1", "quick"},
			includeTags: []string{"fast", "quick", "speed"},
			excludeTags: nil,
			want:        true,
		},
		{
			name:        "multiple exclude tags, one matches - should not match",
			moduleTags:  []string{"tag1", "slow"},
			includeTags: nil,
			excludeTags: []string{"intrusive", "slow", "heavy"},
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := planner.matchesTags(tt.moduleTags, tt.includeTags, tt.excludeTags)
			if got != tt.want {
				t.Errorf("matchesTags() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test logUnprocessedModules logs unprocessed modules with unmet dependencies
func TestPlanner_logUnprocessedModules(t *testing.T) {
	planner, _ := NewDAGPlanner(nil, nil)

	// Create modules with dependencies
	module1Meta := ModuleMetadata{
		Name: "module1",
		Consumes: []DataContractEntry{
			{Key: "missing.key1"},
			{Key: "missing.key2"},
		},
	}
	module2Meta := ModuleMetadata{
		Name: "module2",
		Consumes: []DataContractEntry{
			{Key: "available.key"},
		},
	}

	candidateModules := []ModuleFactory{
		fakeFactory(module1Meta),
		fakeFactory(module2Meta),
	}

	// Only module2 was added (module1 has unmet dependencies)
	moduleTypesAddedToDAG := map[string]bool{
		"module2": true,
	}

	availableDataKeys := map[string]string{
		"available.key": "some_module",
	}

	// This should log module1 with unmet dependencies (missing.key1, missing.key2)
	// Test passes if no panic occurs (function is mainly for logging)
	planner.logUnprocessedModules(candidateModules, moduleTypesAddedToDAG, availableDataKeys)

	// Test case where all modules were added (no logging)
	allAddedModules := map[string]bool{
		"module1": true,
		"module2": true,
	}
	planner.logUnprocessedModules(candidateModules, allAddedModules, availableDataKeys)
}

func TestScanIntent_Profile_or_Level_or_Default(t *testing.T) {
	tests := []struct {
		name   string
		intent ScanIntent
		want   string
	}{
		{
			name:   "Profile set",
			intent: ScanIntent{Profile: "quick_discovery", Level: "light"},
			want:   "quick_discovery",
		},
		{
			name:   "Level set, Profile empty",
			intent: ScanIntent{Profile: "", Level: "comprehensive"},
			want:   "comprehensive",
		},
		{
			name:   "Neither Profile nor Level set",
			intent: ScanIntent{Profile: "", Level: ""},
			want:   "default_scan",
		},
		{
			name:   "Profile set, Level empty",
			intent: ScanIntent{Profile: "full_scan", Level: ""},
			want:   "full_scan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.intent.Profile_or_Level_or_Default()
			if got != tt.want {
				t.Errorf("Profile_or_Level_or_Default() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDAGPlanner_PlanDAG_NoModulesSelected(t *testing.T) {
	// Planner with empty registry
	planner, err := NewDAGPlanner(map[string]ModuleFactory{}, nil)
	if err != nil {
		t.Fatalf("NewDAGPlanner error: %v", err)
	}
	intent := ScanIntent{Targets: []string{"127.0.0.1"}}
	dag, err := planner.PlanDAG(intent)
	if err == nil {
		t.Fatalf("expected error when no modules are selected, got nil")
	}
	if dag != nil {
		t.Fatalf("expected nil DAG when no modules are selected, got %+v", dag)
	}
}

func TestDAGPlanner_PlanDAG_FailsWhenNoNodesPlanned(t *testing.T) {
	// Registry with a module that has unmet dependencies
	meta := ModuleMetadata{
		Name:     "mod1",
		Type:     ScanModuleType,
		Consumes: []DataContractEntry{{Key: "nonexistent.key"}},
		Produces: []DataContractEntry{{Key: "output.key"}},
	}
	registry := map[string]ModuleFactory{
		"mod1": fakeFactory(meta),
	}
	planner, err := NewDAGPlanner(registry, nil)
	if err != nil {
		t.Fatalf("NewDAGPlanner error: %v", err)
	}
	intent := ScanIntent{Targets: []string{"127.0.0.1"}}
	dag, err := planner.PlanDAG(intent)
	if err == nil {
		t.Fatalf("expected error when no nodes are planned, got nil")
	}
	if dag != nil {
		t.Fatalf("expected nil DAG when no nodes are planned, got %+v", dag)
	}
}

func TestDAGPlanner_PlanDAG_SuccessfulPlanning(t *testing.T) {
	// Registry with a simple chain: discovery -> scan -> report
	discoveryMeta := ModuleMetadata{
		Name: "tcp-port-discovery", Type: DiscoveryModuleType,
		Produces:     []DataContractEntry{{Key: "discovery.open_tcp_ports"}},
		ConfigSchema: map[string]ParameterDefinition{},
	}
	scanMeta := ModuleMetadata{
		Name: "banner-grabber", Type: ScanModuleType,
		Consumes:     []DataContractEntry{{Key: "discovery.open_tcp_ports"}},
		Produces:     []DataContractEntry{{Key: "service.banner.tcp"}},
		ConfigSchema: map[string]ParameterDefinition{},
	}
	reporterMeta := ModuleMetadata{
		Name: "json-reporter", Type: ReportingModuleType,
		ConfigSchema: map[string]ParameterDefinition{},
	}
	registry := map[string]ModuleFactory{
		discoveryMeta.Name: fakeFactory(discoveryMeta),
		scanMeta.Name:      fakeFactory(scanMeta),
		reporterMeta.Name:  fakeFactory(reporterMeta),
	}
	planner, err := NewDAGPlanner(registry, nil)
	if err != nil {
		t.Fatalf("NewDAGPlanner error: %v", err)
	}
	intent := ScanIntent{Targets: []string{"127.0.0.1"}}
	dag, err := planner.PlanDAG(intent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dag == nil {
		t.Fatalf("expected DAG, got nil")
	}
	if len(dag.Nodes) != 3 {
		t.Fatalf("expected 3 nodes in DAG, got %d", len(dag.Nodes))
	}
	// Check node types
	found := map[string]bool{}
	for _, n := range dag.Nodes {
		found[n.ModuleType] = true
	}
	if !found["tcp-port-discovery"] || !found["banner-grabber"] || !found["json-reporter"] {
		t.Fatalf("expected all modules in DAG, got %+v", found)
	}
}

func TestDAGPlanner_selectDefaultModules(t *testing.T) {
	// Setup fake modules
	discoveryMeta := ModuleMetadata{
		Name: "tcp-port-discovery",
		Type: DiscoveryModuleType,
		Tags: []string{"safe"},
	}
	scanMeta := ModuleMetadata{
		Name: "banner-grabber",
		Type: ScanModuleType,
		Tags: []string{"scan"},
	}
	intrusiveScanMeta := ModuleMetadata{
		Name: "intrusive-scanner",
		Type: ScanModuleType,
		Tags: []string{"intrusive"},
	}
	evalMeta := ModuleMetadata{
		Name: "vuln-evaluator",
		Type: EvaluationModuleType,
		Tags: []string{"eval"},
	}
	otherMeta := ModuleMetadata{
		Name: "other-module",
		Type: ParseModuleType,
		Tags: []string{"parse"},
	}

	registry := map[string]ModuleFactory{
		discoveryMeta.Name:     fakeFactory(discoveryMeta),
		scanMeta.Name:          fakeFactory(scanMeta),
		intrusiveScanMeta.Name: fakeFactory(intrusiveScanMeta),
		evalMeta.Name:          fakeFactory(evalMeta),
		otherMeta.Name:         fakeFactory(otherMeta),
	}

	planner, err := NewDAGPlanner(registry, nil)
	if err != nil {
		t.Fatalf("NewDAGPlanner error: %v", err)
	}

	t.Run("default profile excludes intrusive and includes discovery/scan", func(t *testing.T) {
		intent := ScanIntent{}
		selected := planner.selectDefaultModules(intent)
		found := map[string]bool{}
		for _, factory := range selected {
			found[factory().Metadata().Name] = true
		}
		if !found["tcp-port-discovery"] {
			t.Error("expected tcp-port-discovery in default modules")
		}
		if !found["banner-grabber"] {
			t.Error("expected banner-grabber in default modules")
		}
		if found["intrusive-scanner"] {
			t.Error("did not expect intrusive-scanner in default modules")
		}
		if found["vuln-evaluator"] {
			t.Error("did not expect vuln-evaluator unless EnableVulnChecks is true")
		}
		if found["other-module"] {
			t.Error("did not expect other-module (parse) in default modules")
		}
	})

	t.Run("default profile with EnableVulnChecks includes evaluation modules", func(t *testing.T) {
		intent := ScanIntent{EnableVulnChecks: true}
		selected := planner.selectDefaultModules(intent)
		found := map[string]bool{}
		for _, factory := range selected {
			found[factory().Metadata().Name] = true
		}
		if !found["vuln-evaluator"] {
			t.Error("expected vuln-evaluator in default modules when EnableVulnChecks is true")
		}
	})

	t.Run("default profile with includeTags filters modules", func(t *testing.T) {
		intent := ScanIntent{IncludeTags: []string{"scan"}}
		selected := planner.selectDefaultModules(intent)
		found := map[string]bool{}
		for _, factory := range selected {
			found[factory().Metadata().Name] = true
		}
		if !found["banner-grabber"] {
			t.Error("expected banner-grabber due to includeTags")
		}
		if found["tcp-port-discovery"] {
			t.Error("did not expect tcp-port-discovery (missing 'scan' tag)")
		}
	})

	t.Run("default profile with excludeTags filters modules", func(t *testing.T) {
		intent := ScanIntent{ExcludeTags: []string{"scan"}}
		selected := planner.selectDefaultModules(intent)
		found := map[string]bool{}
		for _, factory := range selected {
			found[factory().Metadata().Name] = true
		}
		if found["banner-grabber"] {
			t.Error("did not expect banner-grabber due to excludeTags")
		}
		if !found["tcp-port-discovery"] {
			t.Error("expected tcp-port-discovery (does not have 'scan' tag)")
		}
	})
}

func TestDAGPlanner_ensureReporter(t *testing.T) {
	// Setup fake modules
	reporterMeta := ModuleMetadata{
		Name: "json-reporter",
		Type: ReportingModuleType,
		Tags: []string{"report"},
	}
	otherMeta := ModuleMetadata{
		Name: "banner-grabber",
		Type: ScanModuleType,
		Tags: []string{"scan"},
	}
	anotherReporterMeta := ModuleMetadata{
		Name: "xml-reporter",
		Type: ReportingModuleType,
		Tags: []string{"report", "xml"},
	}

	t.Run("returns unchanged if reporter present", func(t *testing.T) {
		registry := map[string]ModuleFactory{
			reporterMeta.Name: fakeFactory(reporterMeta),
			otherMeta.Name:    fakeFactory(otherMeta),
		}
		planner, _ := NewDAGPlanner(registry, nil)
		selected := []ModuleFactory{fakeFactory(otherMeta), fakeFactory(reporterMeta)}
		intent := ScanIntent{}
		result := planner.ensureReporter(selected, intent)
		foundReporter := false
		for _, f := range result {
			if f().Metadata().Type == ReportingModuleType {
				foundReporter = true
			}
		}
		if !foundReporter {
			t.Error("expected reporter to be present")
		}
		if len(result) != len(selected) {
			t.Errorf("expected unchanged selected, got %d, want %d", len(result), len(selected))
		}
	})

	t.Run("adds reporter if missing", func(t *testing.T) {
		registry := map[string]ModuleFactory{
			reporterMeta.Name: fakeFactory(reporterMeta),
			otherMeta.Name:    fakeFactory(otherMeta),
		}
		planner, _ := NewDAGPlanner(registry, nil)
		selected := []ModuleFactory{fakeFactory(otherMeta)}
		intent := ScanIntent{}
		result := planner.ensureReporter(selected, intent)
		foundReporter := false
		for _, f := range result {
			if f().Metadata().Type == ReportingModuleType {
				foundReporter = true
			}
		}
		if !foundReporter {
			t.Error("expected reporter to be added")
		}
		if len(result) != 2 {
			t.Errorf("expected 2 modules after adding reporter, got %d", len(result))
		}
	})

	t.Run("does not add reporter if none matches tags", func(t *testing.T) {
		registry := map[string]ModuleFactory{
			reporterMeta.Name:        fakeFactory(reporterMeta),
			anotherReporterMeta.Name: fakeFactory(anotherReporterMeta),
			otherMeta.Name:           fakeFactory(otherMeta),
		}
		planner, _ := NewDAGPlanner(registry, nil)
		selected := []ModuleFactory{fakeFactory(otherMeta)}
		intent := ScanIntent{IncludeTags: []string{"nonexistent"}}
		result := planner.ensureReporter(selected, intent)
		foundReporter := false
		for _, f := range result {
			if f().Metadata().Type == ReportingModuleType {
				foundReporter = true
			}
		}
		if foundReporter {
			t.Error("did not expect reporter to be added due to unmatched tags")
		}
		if len(result) != 1 {
			t.Errorf("expected 1 module, got %d", len(result))
		}
	})

	t.Run("returns empty if selected is empty", func(t *testing.T) {
		registry := map[string]ModuleFactory{
			reporterMeta.Name: fakeFactory(reporterMeta),
		}
		planner, _ := NewDAGPlanner(registry, nil)
		selected := []ModuleFactory{}
		intent := ScanIntent{}
		result := planner.ensureReporter(selected, intent)
		if len(result) != 0 {
			t.Errorf("expected empty slice, got %d", len(result))
		}
	})
}

func TestDAGPlanner_addParseModules(t *testing.T) {
	// Setup fake modules
	parseMeta1 := ModuleMetadata{
		Name: "http-parser",
		Type: ParseModuleType,
		Tags: []string{"parse", "http"},
	}
	parseMeta2 := ModuleMetadata{
		Name: "dns-parser",
		Type: ParseModuleType,
		Tags: []string{"parse", "dns"},
	}
	nonParseMeta := ModuleMetadata{
		Name: "banner-grabber",
		Type: ScanModuleType,
		Tags: []string{"scan"},
	}

	registry := map[string]ModuleFactory{
		parseMeta1.Name:   fakeFactory(parseMeta1),
		parseMeta2.Name:   fakeFactory(parseMeta2),
		nonParseMeta.Name: fakeFactory(nonParseMeta),
	}

	planner, err := NewDAGPlanner(registry, nil)
	if err != nil {
		t.Fatalf("NewDAGPlanner error: %v", err)
	}

	t.Run("adds all parse modules when no tag filters", func(t *testing.T) {
		selected := []ModuleFactory{}
		intent := ScanIntent{}
		result := planner.addParseModules(selected, registry, intent)
		found := map[string]bool{}
		for _, f := range result {
			meta := f().Metadata()
			if meta.Type == ParseModuleType {
				found[meta.Name] = true
			}
		}
		if !found["http-parser"] || !found["dns-parser"] {
			t.Errorf("expected both parse modules, got %+v", found)
		}
	})

	t.Run("filters parse modules by includeTags", func(t *testing.T) {
		selected := []ModuleFactory{}
		intent := ScanIntent{IncludeTags: []string{"dns"}}
		result := planner.addParseModules(selected, registry, intent)
		found := map[string]bool{}
		for _, f := range result {
			meta := f().Metadata()
			if meta.Type == ParseModuleType {
				found[meta.Name] = true
			}
		}
		if !found["dns-parser"] {
			t.Error("expected dns-parser due to includeTags")
		}
		if found["http-parser"] {
			t.Error("did not expect http-parser due to missing includeTags")
		}
	})

	t.Run("filters parse modules by excludeTags", func(t *testing.T) {
		selected := []ModuleFactory{}
		intent := ScanIntent{ExcludeTags: []string{"http"}}
		result := planner.addParseModules(selected, registry, intent)
		found := map[string]bool{}
		for _, f := range result {
			meta := f().Metadata()
			if meta.Type == ParseModuleType {
				found[meta.Name] = true
			}
		}
		if found["http-parser"] {
			t.Error("did not expect http-parser due to excludeTags")
		}
		if !found["dns-parser"] {
			t.Error("expected dns-parser to be present")
		}
	})

	t.Run("does not add non-parse modules", func(t *testing.T) {
		selected := []ModuleFactory{}
		intent := ScanIntent{}
		result := planner.addParseModules(selected, registry, intent)
		for _, f := range result {
			if f().Metadata().Type != ParseModuleType {
				t.Error("did not expect non-parse module in result")
			}
		}
	})

	t.Run("appends to existing selected slice", func(t *testing.T) {
		// Start with one selected module
		selected := []ModuleFactory{fakeFactory(nonParseMeta)}
		intent := ScanIntent{}
		result := planner.addParseModules(selected, registry, intent)
		foundParse := 0
		foundNonParse := 0
		for _, f := range result {
			if f().Metadata().Type == ParseModuleType {
				foundParse++
			} else {
				foundNonParse++
			}
		}
		if foundNonParse != 1 {
			t.Errorf("expected 1 non-parse module, got %d", foundNonParse)
		}
		if foundParse != 2 {
			t.Errorf("expected 2 parse modules, got %d", foundParse)
		}
	})
}
