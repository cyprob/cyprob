# Tech-Tagger Roadmap

Date: February 16, 2026  
Last Updated: February 16, 2026

## 1) Context
This roadmap exists to make tech tag expansion predictable, low-risk, and measurable after the initial stabilization work.

Phase 1 established a canonical tag source-of-truth, normalized alias handling, mail-focused tag coverage, and strict guards that fail tests when non-canonical tags leak into outputs. This reduced naming drift and made parser/output behavior more consistent for downstream selection and reporting.

## 2) Current State Snapshot
- Canonical tags are centralized in one source-of-truth (constants + normalization layer).
- Parser output and reporting consumption now use the same canonicalization path.
- Mail stack baseline is in place (`mail_service`, `smtp`, `imap`, `pop3`, `webmail`, vendor/product mail tags).
- Guardrails exist: non-canonical tags are blocked by tests.

Known limits:
- Coverage is still uneven across non-mail protocols and middleware families.
- HTTP bias is reduced but not eliminated; some service banners still have low detection depth.
- Rule quality metrics are not yet tracked as a first-class CI artifact.

## 3) Phase 2 Plan (Targeted Expansion)
### Scope
- Add rule families for:
  - Reverse proxies / load balancers
  - Caches and key-value stores
  - Message brokers / queues
  - Common app servers and API gateways
  - Database surface signals (non-invasive banner/header level only)
- Add negative-pattern safeguards for high-risk ambiguous signatures.
- Expand canonical alias map only when required by observed real outputs.

### In-scope
- Rule additions and normalization updates in existing tech-tagger path.
- Golden sample enrichment (positive + negative cases).
- Precision-focused tuning for ambiguous fingerprints.

### Out-of-scope
- New architecture layers.
- Runtime refactor of scan pipeline.
- SNI/OriginalHost redesign.
- Plugin engine redesign.

### Acceptance Criteria
- At least 20 new production-relevant rules added across 4+ families.
- Canonical guard remains green: 0 non-canonical emitted tags.
- False-positive delta for newly added families: <= +2% vs baseline.
- At least 10 new negative samples preventing known mis-tags.
- No regression in `go test ./...` and `go build ./...`.

### Risks & Mitigations
- Risk: Signature overlap causes tag inflation.
  - Mitigation: Require stronger evidence and add explicit negative patterns.
- Risk: Alias expansion introduces semantic duplication.
  - Mitigation: Canonical dictionary review gate before merge.
- Risk: Dataset bias from HTTP-heavy samples.
  - Mitigation: Add protocol-diverse golden samples (SMTP/IMAP/POP3/SSH/TLS banners).

### Effort Estimate
- 1.5 to 2.5 engineering weeks (single engineer), including tests and tuning.

## 4) Phase 3 Plan (Optional / Advanced)
### Scope
- Introduce lightweight scoring/weighting for multi-evidence tag confidence.
- Add per-tag evidence metadata for diagnostics.
- Add quality dashboards for precision/recall trend tracking.

### Acceptance Criteria
- Confidence scoring available for top ambiguous families.
- Measurable FP reduction on ambiguous families (target: >= 20% relative reduction).
- No drop in Phase 2 coverage targets.

### Risk Level
- Medium to high (logic complexity and calibration risk).

### Start Triggers
Start only if all are true:
- Phase 2 acceptance criteria are met for 2 consecutive weekly reviews.
- FP hotspots remain in top-5 recurring misclassification buckets.
- Team has bandwidth for calibration + dataset maintenance.

## 5) Backlog Table
| Item | Phase | Impact | Risk | Effort | Owner | Status |
|---|---|---|---|---|---|---|
| Expand canonical tags for proxy/load-balancer family | Phase 2 | High | Medium | M | CE | todo |
| Add cache/KV service rules (Redis/Memcached patterns) | Phase 2 | High | Medium | M | CE | todo |
| Add broker/queue rules (RabbitMQ/Kafka/ActiveMQ signals) | Phase 2 | High | Medium | M | CE | todo |
| Add app server/API gateway signatures | Phase 2 | Medium | Medium | M | CE | todo |
| Add negative-pattern library for ambiguous server headers | Phase 2 | High | Low | S | CE | todo |
| Build golden sample pack for non-HTTP protocols | Phase 2 | High | Low | M | CE | todo |
| Add CI report artifact for tag precision/FP deltas | Phase 2 | Medium | Low | S | CE | todo |
| Define confidence weighting model for ambiguous tags | Phase 3 | Medium | High | M | CE | todo |
| Add evidence metadata schema for debug outputs | Phase 3 | Medium | Medium | M | CE | todo |
| Add weekly trend dashboard for tag quality | Phase 3 | Medium | Medium | M | CE | todo |

## 6) Metrics & Gates
Track metrics:
- Tag coverage ratio by family (matched services / candidate services).
- False-positive delta per family (vs locked baseline dataset).
- Canonical compliance rate (target: 100%).
- Ambiguous signature error count (weekly).
- Golden sample pass rate.

Phase gates:
- Gate to complete Phase 2:
  - Coverage improvement >= 15% on targeted families.
  - FP delta <= +2% overall and <= +3% in any single family.
  - Canonical compliance 100% for 2 consecutive runs.
- Gate to start Phase 3:
  - Phase 2 gate passed for 2 consecutive weekly checkpoints.
  - Remaining FP hotspots justify scoring investment.

## 7) Execution Rhythm
- Cadence: one weekly roadmap review (30 minutes), one mid-week async status update.
- Reporting format (short):
  - Completed this week
  - Metric deltas (coverage, FP, canonical compliance)
  - Open risks/blockers
  - Next week plan
