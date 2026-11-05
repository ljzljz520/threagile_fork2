package report

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/threagile/threagile/pkg/types"
)

type reportFakeRule struct {
	id     string
	origin string
}

func (r reportFakeRule) Category() *types.RiskCategory {
	return &types.RiskCategory{ID: r.id, Title: r.id + " title"}
}

func (r reportFakeRule) SupportedTags() []string { return nil }

func (r reportFakeRule) RuleOrigin() string {
	if r.origin == "" {
		return types.BuiltInRuleOrigin
	}
	return r.origin
}

func (r reportFakeRule) GenerateRisks(*types.Model) ([]*types.Risk, error) { return nil, nil }

func testModelWithRuleResults() (*types.Model, types.RiskRules, types.RiskRules) {
	builtinRules := types.RiskRules{
		"ok-rule":      reportFakeRule{id: "ok-rule"},
		"skipped-rule": reportFakeRule{id: "skipped-rule"},
		"invalid-rule": reportFakeRule{id: "invalid-rule"},
	}
	customRules := types.RiskRules{
		"external-failed": reportFakeRule{id: "external-failed", origin: types.ExternalRuleOrigin},
	}
	model := &types.Model{
		PartialRiskAnalysis: true,
		RuleExecutionResults: types.RuleExecutionResults{
			{RuleID: "ok-rule", RuleOrigin: types.BuiltInRuleOrigin, Status: types.RuleSuccess, RisksGenerated: 0},
			{RuleID: "skipped-rule", RuleOrigin: types.BuiltInRuleOrigin, Status: types.RuleSkipped, Message: "explicitly skipped via --skip-risk-rules"},
			{RuleID: "invalid-rule", RuleOrigin: types.BuiltInRuleOrigin, Status: types.RuleInvalid, Message: "rule returned 1 invalid risk(s): \"\": risk has no synthetic id assigned"},
			{RuleID: "external-failed", RuleOrigin: types.ExternalRuleOrigin, Status: types.RuleFailed, Message: "exit status 1: kaboom"},
			// plugin that could not even be loaded (rule id is the plugin file name)
			{RuleID: "broken-plugin-file", RuleOrigin: types.ExternalRuleOrigin, Status: types.RuleFailed, Message: "permission denied"},
		},
	}
	return model, builtinRules, customRules
}

func TestRuleStatusHelpers(t *testing.T) {
	model, _, _ := testModelWithRuleResults()

	prefix, _, failed := ruleStatusLabel(model, "skipped-rule")
	assert.Equal(t, "SKIPPED - ", prefix)
	assert.False(t, failed)

	prefix, detail, failed := ruleStatusLabel(model, "external-failed")
	assert.Equal(t, "FAILED - ", prefix)
	assert.True(t, failed)
	assert.Contains(t, detail, "kaboom")

	prefix, _, failed = ruleStatusLabel(model, "invalid-rule")
	assert.Equal(t, "INVALID RESULTS - ", prefix)
	assert.True(t, failed)

	prefix, _, failed = ruleStatusLabel(model, "ok-rule")
	assert.Empty(t, prefix)
	assert.False(t, failed)

	lines := failedRuleExecutionLines(model)
	require.Len(t, lines, 3)
	assert.True(t, strings.Contains(strings.Join(lines, "\n"), "broken-plugin-file"))
	assert.Equal(t, 1, skippedRuleCount(model))
}

func TestAdocRiskRulesChecked_MarksGapsAndStatuses(t *testing.T) {
	model, builtinRules, customRules := testModelWithRuleResults()
	adoc := adocReport{model: model, riskRules: builtinRules}

	tmpFile, err := os.CreateTemp(t.TempDir(), "risk-rules-*.adoc")
	require.NoError(t, err)

	adoc.riskRulesChecked(tmpFile, "model.yaml", nil, "2026-11-05", "test-version", "abc123", customRules)
	require.NoError(t, tmpFile.Close())

	contentBytes, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err)
	content := string(contentBytes)

	assert.Contains(t, content, "Incomplete risk analysis")
	assert.Contains(t, content, "broken-plugin-file")
	assert.Contains(t, content, "permission denied")
	assert.Contains(t, content, "== FAILED - external-failed title")
	assert.Contains(t, content, "Execution result: exit status 1: kaboom")
	assert.Contains(t, content, "== INVALID RESULTS - invalid-rule title")
	assert.Contains(t, content, "== SKIPPED - skipped-rule title")
	assert.Contains(t, content, "== ok-rule title")
	assert.NotContains(t, content, "== FAILED - ok-rule title")
}
