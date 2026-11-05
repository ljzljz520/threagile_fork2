package report

import (
	"sort"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

// ruleStatusLabel maps a rule id to its execution-result label for the "Risk Rules Checked" listings.
// The prefix is prepended to the rule title; detail (if any) gives the failure/skip message.
// The failed flag indicates that the rule did not complete successfully (failed or invalid).
func ruleStatusLabel(parsedModel *types.Model, ruleID string) (prefix string, detail string, failed bool) {
	if parsedModel == nil {
		return "", "", false
	}
	if result, ok := parsedModel.RuleExecutionResults.ByID()[ruleID]; ok {
		switch result.Status {
		case types.RuleSkipped:
			return "SKIPPED - ", result.Message, false
		case types.RuleFailed:
			return "FAILED - ", result.Message, true
		case types.RuleInvalid:
			return "INVALID RESULTS - ", result.Message, true
		}
	}
	return "", "", false
}

// failedRuleExecutionLines returns the sorted list of human-readable lines describing rules
// that failed or returned invalid results, including rules that could not even be loaded
// (their rule id is the plugin file name and hence they do not appear in the normal listings).
func failedRuleExecutionLines(parsedModel *types.Model) []string {
	if parsedModel == nil {
		return nil
	}
	lines := make([]string, 0)
	for _, result := range parsedModel.RuleExecutionResults.Sorted() {
		if result.Status != types.RuleFailed && result.Status != types.RuleInvalid {
			continue
		}
		line := string(result.Status) + " rule " + result.RuleID + " (" + result.RuleOrigin + ")"
		if strings.TrimSpace(result.Message) != "" {
			line += ": " + strings.TrimSpace(result.Message)
		}
		lines = append(lines, line)
	}
	return lines
}

// skippedRuleCount returns how many rules were actively skipped.
func skippedRuleCount(parsedModel *types.Model) int {
	if parsedModel == nil {
		return 0
	}
	count := 0
	for _, result := range parsedModel.RuleExecutionResults {
		if result.Status == types.RuleSkipped {
			count++
		}
	}
	return count
}

func filteredByRiskStatus(parsedModel *types.Model, status types.RiskStatus) []*types.Risk {
	filteredRisks := make([]*types.Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategoryWithCurrentStatus() {
		for _, risk := range risks {
			if risk.RiskStatus == status {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func filteredByRiskFunction(parsedModel *types.Model, function types.RiskFunction) []*types.Risk {
	filteredRisks := make([]*types.Risk, 0)
	for categoryId, risks := range parsedModel.GeneratedRisksByCategory {
		category := parsedModel.GetRiskCategory(categoryId)
		for _, risk := range risks {
			if category.Function == function {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func reduceToRiskStatus(risks []*types.Risk, status types.RiskStatus) []*types.Risk {
	filteredRisks := make([]*types.Risk, 0)
	for _, risk := range risks {
		if risk.RiskStatus == status {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func reduceToFunctionRisk(parsedModel *types.Model, risksByCategory map[string][]*types.Risk, function types.RiskFunction) map[string][]*types.Risk {
	result := make(map[string][]*types.Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := parsedModel.GetRiskCategory(categoryId)
			if category.Function == function {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func reduceToSTRIDERisk(parsedModel *types.Model, risksByCategory map[string][]*types.Risk, stride types.STRIDE) map[string][]*types.Risk {
	result := make(map[string][]*types.Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := parsedModel.GetRiskCategory(categoryId)
			if category != nil && category.STRIDE == stride {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func countRisks(risksByCategory map[string][]*types.Risk) int {
	result := 0
	for _, risks := range risksByCategory {
		result += len(risks)
	}
	return result
}

func totalRiskCount(parsedModel *types.Model) int {
	count := 0
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		count += len(risks)
	}
	return count
}

func sortedTechnicalAssetsByRAAAndTitle(parsedModel *types.Model) []*types.TechnicalAsset {
	assets := make([]*types.TechnicalAsset, 0)
	for _, asset := range parsedModel.TechnicalAssets {
		assets = append(assets, asset)
	}
	sort.Sort(types.ByTechnicalAssetRAAAndTitleSort(assets))
	return assets
}

func sortedKeysOfQuestions(parsedModel *types.Model) []string {
	keys := make([]string, 0)
	for k := range parsedModel.Questions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func filteredBySeverity(parsedModel *types.Model, severity types.RiskSeverity) []*types.Risk {
	filteredRisks := make([]*types.Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategoryWithCurrentStatus() {
		for _, risk := range risks {
			if risk.Severity == severity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func sortedTechnicalAssetsByRiskSeverityAndTitle(parsedModel *types.Model) []*types.TechnicalAsset {
	assets := make([]*types.TechnicalAsset, 0)
	for _, asset := range parsedModel.TechnicalAssets {
		assets = append(assets, asset)
	}
	sortByTechnicalAssetRiskSeverityAndTitleStillAtRisk(assets, parsedModel)
	return assets
}

func filteredByStillAtRisk(parsedModel *types.Model) []*types.Risk {
	filteredRisks := make([]*types.Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategoryWithCurrentStatus() {
		stillAtRisk := types.ReduceToOnlyStillAtRisk(risks)
		filteredRisks = append(filteredRisks, stillAtRisk...)
	}
	return filteredRisks
}

func identifiedDataBreachProbabilityStillAtRisk(parsedModel *types.Model, dataAsset *types.DataAsset) types.DataBreachProbability {
	highestProbability := types.Improbable
	for _, risk := range filteredByStillAtRisk(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, dataAsset.Id) {
				if risk.DataBreachProbability > highestProbability {
					highestProbability = risk.DataBreachProbability
					break
				}
			}
		}
	}
	return highestProbability
}
