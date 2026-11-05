package types

import "sort"

type RiskRule interface {
	Category() *RiskCategory
	SupportedTags() []string
	GenerateRisks(*Model) ([]*Risk, error)
}

type RiskRules map[string]RiskRule

func (what RiskRules) Merge(rules RiskRules) RiskRules {
	for key, value := range rules {
		what[key] = value
	}

	return what
}

const (
	// BuiltInRuleOrigin marks rules compiled into the binary.
	BuiltInRuleOrigin = "builtin"
	// ScriptRuleOrigin marks rules loaded from embedded or plugin YAML scripts.
	ScriptRuleOrigin = "script"
	// ExternalRuleOrigin marks rules executed as external executables (plugins).
	ExternalRuleOrigin = "external"
)

// RiskRuleWithOrigin is optionally implemented by rules that declare how they are provided.
// Rules not implementing it are treated as built-in rules.
type RiskRuleWithOrigin interface {
	RuleOrigin() string
}

// RuleExecutionStatus is the unified outcome of a single risk rule execution.
type RuleExecutionStatus string

const (
	// RuleSuccess means the rule executed without error. RisksGenerated may be zero,
	// which is an explicit "ran successfully with no findings" result.
	RuleSuccess RuleExecutionStatus = "success"
	// RuleSkipped means the rule was actively skipped by the user (e.g. via --skip-risk-rules).
	RuleSkipped RuleExecutionStatus = "skipped"
	// RuleFailed means the rule could not be executed at all (load error, execution error, panic).
	RuleFailed RuleExecutionStatus = "failed"
	// RuleInvalid means the rule executed, but returned risks that failed validation
	// (unknown category, dangling references, duplicate synthetic IDs, ...).
	RuleInvalid RuleExecutionStatus = "invalid"
)

// RejectedRisk describes a single generated risk that was not accepted due to validation errors.
type RejectedRisk struct {
	SyntheticId string   `json:"synthetic_id,omitempty" yaml:"synthetic_id,omitempty"`
	Title       string   `json:"title,omitempty" yaml:"title,omitempty"`
	Reasons     []string `json:"reasons" yaml:"reasons"`
}

// RuleExecutionResult is the unified execution result of one risk rule.
type RuleExecutionResult struct {
	// RuleID is the category ID of the rule, or (for rules that could not be loaded) the plugin file name.
	RuleID string `json:"rule_id" yaml:"rule_id"`
	// RuleOrigin is one of builtin, script, or external.
	RuleOrigin string `json:"rule_origin" yaml:"rule_origin"`
	// Status is one of success, skipped, failed, or invalid.
	Status RuleExecutionStatus `json:"status" yaml:"status"`
	// RisksGenerated counts the risks that were actually accepted for this rule.
	RisksGenerated int `json:"risks_generated" yaml:"risks_generated"`
	// Message carries the error text for failed/invalid rules or the skip reason.
	Message string `json:"message,omitempty" yaml:"message,omitempty"`
	// RejectedRisks lists the individual risks of an invalid rule that were dropped.
	RejectedRisks []RejectedRisk `json:"rejected_risks,omitempty" yaml:"rejected_risks,omitempty"`
}

// RuleExecutionResults keeps one result per executed (or attempted) risk rule.
type RuleExecutionResults []*RuleExecutionResult

func (what RuleExecutionResults) Sorted() RuleExecutionResults {
	sorted := make(RuleExecutionResults, len(what))
	copy(sorted, what)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].RuleID == sorted[j].RuleID {
			return sorted[i].RuleOrigin < sorted[j].RuleOrigin
		}
		return sorted[i].RuleID < sorted[j].RuleID
	})
	return sorted
}

func (what RuleExecutionResults) ByID() map[string]*RuleExecutionResult {
	result := make(map[string]*RuleExecutionResult, len(what))
	for _, entry := range what {
		result[entry.RuleID] = entry
	}
	return result
}

// HasFailures reports whether any rule failed to execute or returned invalid results.
// Explicitly skipped rules and successful runs without findings are not failures.
func (what RuleExecutionResults) HasFailures() bool {
	for _, entry := range what {
		if entry.Status == RuleFailed || entry.Status == RuleInvalid {
			return true
		}
	}
	return false
}

// RuleExecutionSummary summarizes the execution results for JSON output and reports.
type RuleExecutionSummary struct {
	// PartialAnalysis is true when failed/invalid rules were tolerated via explicit opt-in.
	PartialAnalysis bool `json:"partial_analysis" yaml:"partial_analysis"`
	TotalRules      int  `json:"total_rules" yaml:"total_rules"`
	// Succeeded counts all rules that ran without error (including zero findings).
	Succeeded int `json:"succeeded" yaml:"succeeded"`
	// SucceededWithoutFindings counts rules that ran without error and generated no risks.
	SucceededWithoutFindings int                  `json:"succeeded_without_findings" yaml:"succeeded_without_findings"`
	Skipped                  int                  `json:"skipped" yaml:"skipped"`
	Failed                   int                  `json:"failed" yaml:"failed"`
	Invalid                  int                  `json:"invalid" yaml:"invalid"`
	Results                  RuleExecutionResults `json:"results" yaml:"results"`
}

func (what RuleExecutionResults) Summary(partialAnalysis bool) *RuleExecutionSummary {
	summary := &RuleExecutionSummary{
		PartialAnalysis: partialAnalysis,
		TotalRules:      len(what),
		Results:         what.Sorted(),
	}
	for _, entry := range what {
		switch entry.Status {
		case RuleSuccess:
			summary.Succeeded++
			if entry.RisksGenerated == 0 {
				summary.SucceededWithoutFindings++
			}
		case RuleSkipped:
			summary.Skipped++
		case RuleFailed:
			summary.Failed++
		case RuleInvalid:
			summary.Invalid++
		}
	}
	return summary
}

// RuleOriginOf reports how a rule is provided (builtin, script, external).
func RuleOriginOf(rule RiskRule) string {
	if rule == nil {
		return BuiltInRuleOrigin
	}
	if withOrigin, ok := rule.(RiskRuleWithOrigin); ok {
		if origin := withOrigin.RuleOrigin(); len(origin) > 0 {
			return origin
		}
	}
	return BuiltInRuleOrigin
}
