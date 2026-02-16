package scanexec

import (
	"context"
	"fmt"
	"maps"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/storage"
)

type dagPlanner interface {
	PlanDAG(intent engine.ScanIntent) (*engine.DAGDefinition, error)
}

// Service orchestrates scan execution using the engine planner/orchestrator.
type orchestrator interface {
	Run(ctx context.Context, inputs map[string]any) (map[string]any, error)
}

type ProgressSink interface {
	OnEvent(ProgressEvent)
}

type ProgressEvent struct {
	Phase     string
	ModuleID  string
	Module    string
	Status    string
	Message   string
	Timestamp time.Time
}

type Service struct {
	plannerFactory      func(context.Context) (dagPlanner, error)
	orchestratorFactory func(*engine.DAGDefinition) (orchestrator, error)
	progressSink        ProgressSink
	storage             storage.Backend
}

// NewService builds a Service with default dependencies.
func NewService() *Service {
	return &Service{
		plannerFactory: func(ctx context.Context) (dagPlanner, error) {
			// Extract ConfigManager from AppManager in context
			var configMgr engine.ConfigManager
			if appMgr, ok := ctx.Value(engine.AppManagerKey).(engine.Manager); ok && appMgr != nil {
				configMgr = appMgr.Config()
			}
			return engine.NewDAGPlanner(engine.GetRegisteredModuleFactories(), configMgr)
		},
		orchestratorFactory: func(def *engine.DAGDefinition) (orchestrator, error) {
			return engine.NewOrchestrator(def)
		},
	}
}

// WithProgressSink attaches a sink to receive progress notifications.
func (s *Service) WithProgressSink(sink ProgressSink) *Service {
	s.progressSink = sink
	return s
}

// WithStorage attaches a storage backend for persisting scan results.
func (s *Service) WithStorage(backend storage.Backend) *Service {
	s.storage = backend
	return s
}

// WithPlannerFactory overrides planner construction for testing.
func (s *Service) WithPlannerFactory(factory func(context.Context) (dagPlanner, error)) *Service {
	s.plannerFactory = factory
	return s
}

// WithOrchestratorFactory allows replacing the orchestrator constructor (useful for tests).
func (s *Service) WithOrchestratorFactory(factory func(*engine.DAGDefinition) (orchestrator, error)) *Service {
	s.orchestratorFactory = factory
	return s
}

// Run executes the scan pipeline using provided parameters and context carrying AppManager.
func (s *Service) Run(ctx context.Context, params Params) (*Result, error) {
	// Validate that context contains AppManager (required for engine operation)
	switch ctx.Value(engine.AppManagerKey).(type) {
	case *engine.AppManager, engine.Manager:
		// Valid AppManager found in context
	default:
		return nil, fmt.Errorf("app manager missing from context")
	}

	// Generate scan ID and start time
	scanID := uuid.New().String()
	startTime := time.Now()

	// Create initial scan metadata if storage is available
	if s.storage != nil {
		targetStr := ""
		if len(params.Targets) > 0 {
			targetStr = params.Targets[0]
			if len(params.Targets) > 1 {
				targetStr = fmt.Sprintf("%s (and %d more)", params.Targets[0], len(params.Targets)-1)
			}
		}

		metadata := &storage.ScanMetadata{
			ID:              scanID,
			OrgID:           "default",
			UserID:          "local",
			Target:          targetStr,
			Status:          "running",
			StartedAt:       startTime,
			HostCount:       0,
			VulnCount:       storage.VulnCounts{},
			StorageLocation: fmt.Sprintf("scans/default/%s", scanID),
		}

		if err := s.storage.Scans().Create(ctx, "default", metadata); err != nil {
			log.Warn().
				Str("component", "scanexec").
				Str("scan_id", scanID).
				Err(err).
				Msg("Failed to create scan metadata in storage, continuing without persistence")
		} else {
			log.Info().
				Str("component", "scanexec").
				Str("scan_id", scanID).
				Msg("Created scan metadata in storage")
		}
	}

	planner, err := s.plannerFactory(ctx)
	if err != nil {
		// Update scan status to failed if storage available
		s.updateScanStatus(ctx, scanID, "failed", err.Error(), startTime)
		return nil, fmt.Errorf("init planner: %w", err)
	}
	s.emit("plan", "", "planner", "start", "")

	intent := engine.ScanIntent{
		Targets:          params.Targets,
		Profile:          params.Profile,
		Level:            params.Level,
		IncludeTags:      params.IncludeTags,
		ExcludeTags:      params.ExcludeTags,
		EnableVulnChecks: params.EnableVuln,
		CustomPortConfig: params.Ports,
		CustomTimeout:    params.CustomTimeout,
		EnablePing:       params.EnablePing,
		PingCount:        params.PingCount,
		AllowLoopback:    params.AllowLoopback,
		Concurrency:      params.Concurrency,
		DiscoveryOnly:    params.OnlyDiscover,
		SkipDiscovery:    params.SkipDiscover,
	}
	if intent.DiscoveryOnly {
		intent.EnableVulnChecks = false
	}

	dagDefinition, err := planner.PlanDAG(intent)
	if err != nil {
		s.updateScanStatus(ctx, scanID, "failed", err.Error(), startTime)
		return nil, fmt.Errorf("plan dag: %w", err)
	}
	if dagDefinition == nil || len(dagDefinition.Nodes) == 0 {
		s.updateScanStatus(ctx, scanID, "failed", "planner produced empty dag", startTime)
		return nil, fmt.Errorf("planner produced empty dag")
	}
	s.emit("plan", "", "planner", "completed", fmt.Sprintf("nodes=%d", len(dagDefinition.Nodes)))

	orchestrator, err := s.orchestratorFactory(dagDefinition)
	if err != nil {
		s.updateScanStatus(ctx, scanID, "failed", err.Error(), startTime)
		return nil, fmt.Errorf("init orchestrator: %w", err)
	}

	inputs := map[string]any{
		"config.targets":              params.Targets,
		"config.original_cli_targets": params.Targets,
		"config.output.format":        params.OutputFormat,
	}
	maps.Copy(inputs, params.RawInputs)

	s.emit("run", "", dagDefinition.Name, "start", "")
	// Use ctx (not appMgr.Context()) to preserve context values like output.OutputKey
	// This enables real-time progress reporting from modules
	dataCtx, runErr := orchestrator.Run(ctx, inputs)
	status := statusFromError(runErr)
	s.emit("run", "", dagDefinition.Name, status, "")

	// Update scan status in storage
	errorMsg := ""
	if runErr != nil {
		errorMsg = runErr.Error()
	}
	s.updateScanStatus(ctx, scanID, status, errorMsg, startTime)

	// Extract and update scan statistics from dataCtx if available
	s.updateScanStatistics(ctx, scanID, dataCtx)

	result := &Result{
		RunID:      scanID,
		StartTime:  startTime.Format(time.RFC3339),
		EndTime:    time.Now().Format(time.RFC3339),
		Status:     status,
		Findings:   dataCtx,
		RawContext: dataCtx,
	}

	return result, runErr
}

func statusFromError(err error) string {
	if err != nil {
		return "failed"
	}
	return "completed"
}

func (s *Service) emit(phase, moduleID, module, status, msg string) {
	if s.progressSink == nil {
		return
	}
	s.progressSink.OnEvent(ProgressEvent{
		Phase:     phase,
		ModuleID:  moduleID,
		Module:    module,
		Status:    status,
		Message:   msg,
		Timestamp: time.Now(),
	})
}

// updateScanStatus updates the scan status and completion time in storage.
func (s *Service) updateScanStatus(ctx context.Context, scanID, status, errorMsg string, startTime time.Time) {
	if s.storage == nil {
		return
	}

	updates := storage.ScanUpdates{
		Status: &status,
	}

	if errorMsg != "" {
		updates.ErrorMessage = &errorMsg
	}

	// Set completion time and duration if scan finished
	if status == "completed" || status == "failed" {
		completedAt := time.Now()
		duration := int(completedAt.Sub(startTime).Seconds())
		updates.CompletedAt = &completedAt
		updates.Duration = &duration
	}

	if err := s.storage.Scans().Update(ctx, "default", scanID, updates); err != nil {
		log.Warn().
			Str("component", "scanexec").
			Str("scan_id", scanID).
			Err(err).
			Msg("Failed to update scan status in storage")
	} else {
		log.Debug().
			Str("component", "scanexec").
			Str("scan_id", scanID).
			Str("status", status).
			Msg("Updated scan status in storage")
	}
}

// updateScanStatistics extracts statistics from dataCtx and updates storage.
func (s *Service) updateScanStatistics(ctx context.Context, scanID string, dataCtx map[string]any) {
	if s.storage == nil || dataCtx == nil {
		return
	}

	updates := storage.ScanUpdates{}

	// Extract host count from discovery results
	if liveHosts, ok := dataCtx["discovery.live_hosts"]; ok {
		if hosts, ok := liveHosts.([]any); ok {
			count := len(hosts)
			updates.HostCount = &count
		}
	}

	// Extract service count from scan results
	if services, ok := dataCtx["scan.services"]; ok {
		if svcList, ok := services.([]any); ok {
			count := len(svcList)
			updates.ServiceCount = &count
		}
	}

	// Extract vulnerability counts from evaluation results
	if vulns, ok := dataCtx["vulnerability.results"]; ok {
		if vulnList, ok := vulns.([]any); ok {
			vulnCounts := storage.VulnCounts{}
			for _, v := range vulnList {
				if vulnMap, ok := v.(map[string]any); ok {
					if severity, ok := vulnMap["severity"].(string); ok {
						switch severity {
						case "CRITICAL":
							vulnCounts.Critical++
						case "HIGH":
							vulnCounts.High++
						case "MEDIUM":
							vulnCounts.Medium++
						case "LOW":
							vulnCounts.Low++
						case "INFO":
							vulnCounts.Info++
						}
					}
				}
			}
			updates.VulnCount = &vulnCounts
		}
	}

	// Only update if we have statistics to update
	if updates.HostCount != nil || updates.ServiceCount != nil || updates.VulnCount != nil {
		if err := s.storage.Scans().Update(ctx, "default", scanID, updates); err != nil {
			log.Warn().
				Str("component", "scanexec").
				Str("scan_id", scanID).
				Err(err).
				Msg("Failed to update scan statistics in storage")
		} else {
			log.Debug().
				Str("component", "scanexec").
				Str("scan_id", scanID).
				Msg("Updated scan statistics in storage")
		}
	}
}
