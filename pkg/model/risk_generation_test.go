package model

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

type silentProgressReporter struct{}

func (silentProgressReporter) Info(a ...any)                  {}
func (silentProgressReporter) Warn(a ...any)                  {}
func (silentProgressReporter) Error(a ...any)                 {}
func (silentProgressReporter) Infof(format string, a ...any)  {}
func (silentProgressReporter) Warnf(format string, a ...any)  {}
func (silentProgressReporter) Errorf(format string, a ...any) {}

type fakeRiskRule struct {
	id       string
	origin   string
	tags     []string
	risks    []*types.Risk
	err      error
	panicNow bool
}

func (r *fakeRiskRule) Category() *types.RiskCategory {
	return &types.RiskCategory{ID: r.id, Title: r.id + " title"}
}

func (r *fakeRiskRule) SupportedTags() []string {
	return r.tags
}

func (r *fakeRiskRule) RuleOrigin() string {
	if r.origin == "" {
		return types.BuiltInRuleOrigin
	}
	return r.origin
}

func (r *fakeRiskRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	if r.panicNow {
		panic("boom")
	}
	return r.risks, r.err
}

func newParsedModelForRuleTest(t *testing.T, rules types.RiskRules) *types.Model {
	t.Helper()
	parsedModel, err := ParseModel(&mockConfig{},
		createInputModel(make(map[string]input.TechnicalAsset), make(map[string]input.DataAsset)),
		rules, make(types.RiskRules))
	require.NoError(t, err)
	parsedModel.TechnicalAssets["known-ta"] = &types.TechnicalAsset{Id: "known-ta"}
	return parsedModel
}

func newGeneratedRisk(categoryId, syntheticId string) *types.Risk {
	return &types.Risk{
		CategoryId:                   categoryId,
		SyntheticId:                  syntheticId,
		Title:                        syntheticId,
		Severity:                     types.MediumSeverity,
		MostRelevantTechnicalAssetId: "known-ta",
	}
}

func fakeRules(rules ...*fakeRiskRule) types.RiskRules {
	result := make(types.RiskRules)
	for _, rule := range rules {
		result[rule.id] = rule
	}
	return result
}

func TestApplyRiskGeneration_DistinguishesSuccessZeroFindingsAndSkipped(t *testing.T) {
	rules := fakeRules(
		&fakeRiskRule{id: "zero-findings-rule"},
		&fakeRiskRule{id: "one-finding-rule", risks: []*types.Risk{newGeneratedRisk("one-finding-rule", "one-finding-rule@a")}},
		&fakeRiskRule{id: "skipped-rule", risks: []*types.Risk{newGeneratedRisk("skipped-rule", "skipped-rule@a")}},
	)
	parsedModel := newParsedModelForRuleTest(t, rules)

	results := applyRiskGeneration(parsedModel, rules, nil, []string{"skipped-rule"}, silentProgressReporter{})

	byID := results.ByID()
	require.Contains(t, byID, "zero-findings-rule")
	assert.Equal(t, types.RuleSuccess, byID["zero-findings-rule"].Status)
	assert.Equal(t, 0, byID["zero-findings-rule"].RisksGenerated)

	require.Contains(t, byID, "one-finding-rule")
	assert.Equal(t, types.RuleSuccess, byID["one-finding-rule"].Status)
	assert.Equal(t, 1, byID["one-finding-rule"].RisksGenerated)
	assert.Len(t, parsedModel.GeneratedRisksByCategory["one-finding-rule"], 1)

	require.Contains(t, byID, "skipped-rule")
	assert.Equal(t, types.RuleSkipped, byID["skipped-rule"].Status)
	assert.Empty(t, parsedModel.GeneratedRisksByCategory["skipped-rule"])

	assert.False(t, results.HasFailures())
	summary := results.Summary(false)
	assert.Equal(t, 3, summary.TotalRules)
	assert.Equal(t, 2, summary.Succeeded)
	assert.Equal(t, 1, summary.SucceededWithoutFindings)
	assert.Equal(t, 1, summary.Skipped)
}

func TestApplyRiskGeneration_FailedAndPanickingRulesAreRecordedButDoNotKillOthers(t *testing.T) {
	rules := fakeRules(
		&fakeRiskRule{id: "error-rule", err: assertError("cannot execute")},
		&fakeRiskRule{id: "panic-rule", panicNow: true},
		&fakeRiskRule{id: "ok-rule", origin: types.ScriptRuleOrigin, risks: []*types.Risk{newGeneratedRisk("ok-rule", "ok-rule@a")}},
	)
	parsedModel := newParsedModelForRuleTest(t, rules)

	results := applyRiskGeneration(parsedModel, rules, nil, nil, silentProgressReporter{})

	byID := results.ByID()
	assert.Equal(t, types.RuleFailed, byID["error-rule"].Status)
	assert.Contains(t, byID["error-rule"].Message, "cannot execute")
	assert.Equal(t, types.RuleFailed, byID["panic-rule"].Status)
	assert.Contains(t, byID["panic-rule"].Message, "panicked")
	assert.Equal(t, types.RuleSuccess, byID["ok-rule"].Status)
	assert.Equal(t, types.ScriptRuleOrigin, byID["ok-rule"].RuleOrigin)
	assert.Len(t, parsedModel.GeneratedRisksByCategory["ok-rule"], 1)
	assert.Empty(t, parsedModel.GeneratedRisksByCategory["error-rule"])
	assert.True(t, results.HasFailures())

	summary := results.Summary(false)
	assert.Equal(t, 2, summary.Failed)
	assert.Equal(t, 1, summary.Succeeded)
}

func TestApplyRiskGeneration_InvalidRisksAreRejectedAndRuleMarkedInvalid(t *testing.T) {
	wrongCategory := newGeneratedRisk("some-other-rule", "bad-rule@wrong-category")
	missingSyntheticId := newGeneratedRisk("bad-rule", "")
	danglingReference := newGeneratedRisk("bad-rule", "bad-rule@dangling")
	danglingReference.MostRelevantTechnicalAssetId = "ghost-ta"
	duplicateA := newGeneratedRisk("bad-rule", "bad-rule@dup")
	duplicateB := newGeneratedRisk("bad-rule", "bad-rule@dup")
	validRisk := newGeneratedRisk("bad-rule", "bad-rule@good")

	rules := fakeRules(
		&fakeRiskRule{id: "bad-rule", risks: []*types.Risk{
			nil,
			wrongCategory,
			missingSyntheticId,
			danglingReference,
			duplicateA,
			duplicateB,
			validRisk,
		}},
		&fakeRiskRule{id: "other-rule", risks: []*types.Risk{
			// same synthetic id as the already accepted valid risk: must be rejected, not overwrite
			func() *types.Risk {
				risk := newGeneratedRisk("other-rule", "bad-rule@good")
				return risk
			}(),
		}},
	)
	parsedModel := newParsedModelForRuleTest(t, rules)

	results := applyRiskGeneration(parsedModel, rules, nil, nil, silentProgressReporter{})

	byID := results.ByID()
	assert.Equal(t, types.RuleInvalid, byID["bad-rule"].Status)
	assert.Equal(t, 2, byID["bad-rule"].RisksGenerated)
	assert.Len(t, byID["bad-rule"].RejectedRisks, 5)
	assert.Len(t, parsedModel.GeneratedRisksByCategory["bad-rule"], 2)
	assert.Equal(t, "bad-rule@dup", parsedModel.GeneratedRisksByCategory["bad-rule"][0].SyntheticId)
	assert.Equal(t, "bad-rule@good", parsedModel.GeneratedRisksByCategory["bad-rule"][1].SyntheticId)

	assert.Equal(t, types.RuleInvalid, byID["other-rule"].Status)
	assert.Equal(t, 0, byID["other-rule"].RisksGenerated)
	// the first accepted risk must still be the owner of the synthetic id
	assert.Equal(t, "bad-rule@good", parsedModel.GeneratedRisksBySyntheticId["bad-rule@good"].SyntheticId)
	assert.Equal(t, "bad-rule", parsedModel.GeneratedRisksBySyntheticId["bad-rule@good"].CategoryId)

	assert.True(t, results.HasFailures())
}

func TestApplyRiskGeneration_AppendsInsteadOfOverwritingExistingFindings(t *testing.T) {
	existingRisk := newGeneratedRisk("seed-rule", "seed-rule@existing")
	rules := fakeRules(
		&fakeRiskRule{id: "seed-rule", risks: []*types.Risk{
			newGeneratedRisk("seed-rule", "seed-rule@new"),
			newGeneratedRisk("seed-rule", "seed-rule@existing"), // duplicate: rejected
		}},
	)
	parsedModel := newParsedModelForRuleTest(t, rules)
	parsedModel.GeneratedRisksByCategory["seed-rule"] = []*types.Risk{existingRisk}

	results := applyRiskGeneration(parsedModel, rules, nil, nil, silentProgressReporter{})

	byID := results.ByID()
	assert.Equal(t, types.RuleInvalid, byID["seed-rule"].Status)
	assert.Equal(t, 1, byID["seed-rule"].RisksGenerated)
	// pre-existing finding must survive and the new valid one is appended
	require.Len(t, parsedModel.GeneratedRisksByCategory["seed-rule"], 2)
	assert.Equal(t, "seed-rule@existing", parsedModel.GeneratedRisksByCategory["seed-rule"][0].SyntheticId)
	assert.Equal(t, "seed-rule@new", parsedModel.GeneratedRisksByCategory["seed-rule"][1].SyntheticId)
	assert.Same(t, existingRisk, parsedModel.GeneratedRisksBySyntheticId["seed-rule@existing"])
}

func TestApplyRiskGeneration_ExternalPluginLoadFailuresAreIncluded(t *testing.T) {
	rules := fakeRules(
		&fakeRiskRule{id: "ok-rule", risks: []*types.Risk{newGeneratedRisk("ok-rule", "ok-rule@a")}},
	)
	parsedModel := newParsedModelForRuleTest(t, rules)
	loadFailures := types.RuleExecutionResults{
		{RuleID: "broken-plugin", RuleOrigin: types.ExternalRuleOrigin, Status: types.RuleFailed, Message: "exec format error"},
	}

	results := applyRiskGeneration(parsedModel, rules, loadFailures, nil, silentProgressReporter{})

	byID := results.ByID()
	require.Contains(t, byID, "broken-plugin")
	assert.Equal(t, types.RuleFailed, byID["broken-plugin"].Status)
	assert.Equal(t, types.ExternalRuleOrigin, byID["broken-plugin"].RuleOrigin)
	assert.Equal(t, types.RuleSuccess, byID["ok-rule"].Status)
	assert.True(t, results.HasFailures())
}

func TestLoadCustomRiskRules_MissingPluginIsRecordedAsFailed(t *testing.T) {
	pluginDir := t.TempDir()
	rules, loadResults := LoadCustomRiskRules(pluginDir, []string{"does-not-exist-plugin"}, silentProgressReporter{})

	assert.Empty(t, rules)
	require.Len(t, loadResults, 1)
	assert.Equal(t, "does-not-exist-plugin", loadResults[0].RuleID)
	assert.Equal(t, types.ExternalRuleOrigin, loadResults[0].RuleOrigin)
	assert.Equal(t, types.RuleFailed, loadResults[0].Status)
}

func TestLoadCustomRiskRules_NonExecutablePluginIsRecordedAsFailed(t *testing.T) {
	pluginDir := t.TempDir()
	pluginFile := filepath.Join(pluginDir, "not-executable-plugin")
	require.NoError(t, os.WriteFile(pluginFile, []byte("not a binary"), 0o600))

	rules, loadResults := LoadCustomRiskRules(pluginDir, []string{"not-executable-plugin"}, silentProgressReporter{})

	assert.Empty(t, rules)
	require.Len(t, loadResults, 1)
	assert.Equal(t, types.RuleFailed, loadResults[0].Status)
	assert.NotEmpty(t, loadResults[0].Message)
}

type ruleFailureError string

func (e ruleFailureError) Error() string { return string(e) }

func assertError(message string) error { return ruleFailureError(message) }
