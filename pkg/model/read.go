package model

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

type ReadResult struct {
	ModelInput       *input.Model
	ParsedModel      *types.Model
	IntroTextRAA     string
	BuiltinRiskRules types.RiskRules
	CustomRiskRules  types.RiskRules
}

type explainRiskConfig interface {
}

type explainRiskReporter interface {
}

func (what ReadResult) ExplainRisk(cfg explainRiskConfig, risk string, reporter explainRiskReporter) error {
	return fmt.Errorf("not implemented")
}

// TODO: consider about splitting this function into smaller ones for better reusability

type configReader interface {
	GetBuildTimestamp() string
	GetVerbose() bool
	GetInteractive() bool
	GetAppFolder() string
	GetPluginFolder() string
	GetDataFolder() string
	GetOutputFolder() string
	GetServerFolder() string
	GetTempFolder() string
	GetKeyFolder() string
	GetInputFile() string
	GetImportedInputFile() string
	GetDataFlowDiagramFilenamePNG() string
	GetDataAssetDiagramFilenamePNG() string
	GetDataFlowDiagramFilenameDOT() string
	GetDataAssetDiagramFilenameDOT() string
	GetReportFilename() string
	GetExcelRisksFilename() string
	GetExcelTagsFilename() string
	GetJsonRisksFilename() string
	GetJsonTechnicalAssetsFilename() string
	GetJsonStatsFilename() string
	GetTemplateFilename() string
	GetTechnologyFilename() string
	GetRiskRulePlugins() []string
	GetSkipRiskRules() []string
	GetExecuteModelMacro() string
	GetRiskExcelConfigHideColumns() []string
	GetRiskExcelConfigSortByColumns() []string
	GetRiskExcelConfigWidthOfColumns() map[string]float64
	GetServerMode() bool
	GetDiagramDPI() int
	GetServerPort() int
	GetGraphvizDPI() int
	GetMaxGraphvizDPI() int
	GetBackupHistoryFilesToKeep() int
	GetAddModelTitle() bool
	GetAddLegend() bool
	GetKeepDiagramSourceFiles() bool
	GetIgnoreOrphanedRiskTracking() bool
	GetAllowPartialRiskAnalysis() bool
	GetThreagileVersion() string
	GetProgressReporter() types.ProgressReporter
}

func ReadAndAnalyzeModel(config configReader, builtinRiskRules types.RiskRules, progressReporter types.ProgressReporter) (*ReadResult, error) {
	progressReporter.Infof("Writing into output directory: %v", config.GetOutputFolder())
	progressReporter.Infof("Parsing model: %v", config.GetInputFile())

	customRiskRules, customRuleLoadResults := LoadCustomRiskRules(config.GetPluginFolder(), config.GetRiskRulePlugins(), progressReporter)

	modelInput := new(input.Model).Defaults()
	loadError := modelInput.Load(config.GetInputFile())
	if loadError != nil {
		return nil, fmt.Errorf("unable to load model yaml: %w", loadError)
	}

	result, analysisError := AnalyzeModel(modelInput, config, builtinRiskRules, customRiskRules, customRuleLoadResults, progressReporter)
	if analysisError == nil {
		writeToFile("model yaml", result.ParsedModel, config.GetImportedInputFile(), progressReporter)
	}

	return result, analysisError
}

func AnalyzeModel(modelInput *input.Model, config configReader, builtinRiskRules types.RiskRules, customRiskRules types.RiskRules,
	customRuleLoadResults types.RuleExecutionResults, progressReporter types.ProgressReporter) (*ReadResult, error) {

	parsedModel, parseError := ParseModel(config, modelInput, builtinRiskRules, customRiskRules)
	if parseError != nil {
		return nil, fmt.Errorf("unable to parse model yaml: %w", parseError)
	}

	introTextRAA := applyRAA(parsedModel, progressReporter)

	allowPartial := config.GetAllowPartialRiskAnalysis()
	ruleResults := applyRiskGeneration(parsedModel, builtinRiskRules.Merge(customRiskRules), customRuleLoadResults,
		config.GetSkipRiskRules(), progressReporter)
	parsedModel.RuleExecutionResults = ruleResults
	parsedModel.PartialRiskAnalysis = allowPartial && ruleResults.HasFailures()

	if ruleResults.HasFailures() {
		failedRuleList := make([]string, 0)
		for _, result := range ruleResults {
			if result.Status == types.RuleFailed || result.Status == types.RuleInvalid {
				failedRuleList = append(failedRuleList, fmt.Sprintf("%v (%v): %v", result.RuleID, result.Status, result.Message))
			}
		}
		if !allowPartial {
			return nil, fmt.Errorf("risk rule execution failed for %d rule(s), refusing to report a partial analysis "+
				"(zero findings can no longer be distinguished from rules that did not run); "+
				"re-run with --allow-partial-risk-analysis to explicitly tolerate this:\n  - %v",
				len(failedRuleList), strings.Join(failedRuleList, "\n  - "))
		}
		progressReporter.Warnf("Partial risk analysis explicitly enabled: continuing despite %d failed/invalid rule(s), "+
			"the generated reports and JSON results mark the resulting gaps", len(failedRuleList))
	}

	err := parsedModel.ApplyWildcardRiskTrackingEvaluation(config.GetIgnoreOrphanedRiskTracking(), progressReporter)
	if err != nil {
		return nil, fmt.Errorf("unable to apply wildcard risk tracking evaluation: %w", err)
	}

	err = parsedModel.CheckRiskTracking(config.GetIgnoreOrphanedRiskTracking(), progressReporter)
	if err != nil {
		return nil, fmt.Errorf("unable to check risk tracking: %w", err)
	}

	return &ReadResult{
		ModelInput:       modelInput,
		ParsedModel:      parsedModel,
		IntroTextRAA:     introTextRAA,
		BuiltinRiskRules: builtinRiskRules,
		CustomRiskRules:  customRiskRules,
	}, nil
}

func applyRiskGeneration(parsedModel *types.Model, rules types.RiskRules,
	loadResults types.RuleExecutionResults, skipRiskRules []string,
	progressReporter types.ProgressReporter) types.RuleExecutionResults {
	progressReporter.Info("Applying risk generation")

	results := make(types.RuleExecutionResults, 0, len(rules)+len(loadResults))
	// rules that could not even be loaded already carry a failed execution result
	results = append(results, loadResults...)

	skippedRules := make(map[string]bool)
	for _, id := range skipRiskRules {
		skippedRules[strings.TrimSpace(id)] = true
	}

	// synthetic IDs already present (e.g. individual risk categories from the model YAML):
	// they must never be silently overwritten by rule output
	acceptedSyntheticIds := make(map[string]string)
	for categoryId, existingRisks := range parsedModel.GeneratedRisksByCategory {
		for _, existingRisk := range existingRisks {
			if existingRisk == nil {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(existingRisk.SyntheticId))
			if _, exists := acceptedSyntheticIds[key]; !exists {
				acceptedSyntheticIds[key] = categoryId
			}
		}
	}

	ruleIds := make([]string, 0, len(rules))
	for id := range rules {
		ruleIds = append(ruleIds, id)
	}
	sort.Strings(ruleIds)

	for _, id := range ruleIds {
		rule := rules[id]
		origin := types.RuleOriginOf(rule)

		if skippedRules[id] {
			progressReporter.Infof("Skipping risk rule: %v", id)
			delete(skippedRules, id)
			results = append(results, &types.RuleExecutionResult{
				RuleID:     id,
				RuleOrigin: origin,
				Status:     types.RuleSkipped,
				Message:    "explicitly skipped via --skip-risk-rules",
			})
			continue
		}

		result := &types.RuleExecutionResult{
			RuleID:     id,
			RuleOrigin: origin,
			Status:     types.RuleSuccess,
		}

		category := func() *types.RiskCategory {
			defer func() { _ = recover() }()
			return rule.Category()
		}()
		if rule == nil || category == nil || strings.TrimSpace(category.ID) == "" {
			result.Status = types.RuleFailed
			result.Message = "risk rule does not provide a valid risk category (empty category id)"
			progressReporter.Warnf("Error generating risks for %q: %v", id, result.Message)
			results = append(results, result)
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(category.ID), id) {
			result.Status = types.RuleFailed
			result.Message = fmt.Sprintf("risk rule category id %q does not match its registered rule id %q", category.ID, id)
			progressReporter.Warnf("Error generating risks for %q: %v", id, result.Message)
			results = append(results, result)
			continue
		}

		parsedModel.AddToListOfSupportedTags(rule.SupportedTags())

		newRisks, riskError := generateRisksSafely(rule, parsedModel)
		if riskError != nil {
			result.Status = types.RuleFailed
			result.Message = riskError.Error()
			progressReporter.Warnf("Error generating risks for %q: %v", id, riskError)
			results = append(results, result)
			continue
		}

		acceptedRisks := make([]*types.Risk, 0, len(newRisks))
		rejectedRisks := make([]types.RejectedRisk, 0)
		for _, newRisk := range newRisks {
			rejection := validateGeneratedRisk(id, newRisk, parsedModel, acceptedSyntheticIds)
			if rejection != nil {
				rejectedRisks = append(rejectedRisks, *rejection)
				continue
			}
			acceptedRisks = append(acceptedRisks, newRisk)
			acceptedSyntheticIds[strings.ToLower(strings.TrimSpace(newRisk.SyntheticId))] = id
		}

		if len(rejectedRisks) > 0 {
			result.Status = types.RuleInvalid
			result.RejectedRisks = rejectedRisks
			rejectedDescriptions := make([]string, 0, len(rejectedRisks))
			for _, rejectedRisk := range rejectedRisks {
				rejectedDescriptions = append(rejectedDescriptions,
					fmt.Sprintf("%q: %v", rejectedRisk.SyntheticId, strings.Join(rejectedRisk.Reasons, "; ")))
			}
			result.Message = fmt.Sprintf("rule returned %d invalid risk(s): %v", len(rejectedRisks), strings.Join(rejectedDescriptions, " | "))
			progressReporter.Warnf("Invalid risks generated by %q, dropping %d of %d risk(s): %v",
				id, len(rejectedRisks), len(newRisks), strings.Join(rejectedDescriptions, " | "))
		}

		// append instead of replace so that a bad rule cannot overwrite findings of the same category
		if len(acceptedRisks) > 0 {
			parsedModel.GeneratedRisksByCategory[id] = append(parsedModel.GeneratedRisksByCategory[id], acceptedRisks...)
		}
		result.RisksGenerated = len(acceptedRisks)
		results = append(results, result)
	}

	if len(skippedRules) > 0 {
		keys := make([]string, 0)
		for k := range skippedRules {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		progressReporter.Infof("Unknown risk rules to skip: %v", keys)
	}

	// save also in map keyed by synthetic risk-id (now guaranteed unique, no silent overwrite)
	parsedModel.GeneratedRisksBySyntheticId = make(map[string]*types.Risk)
	for _, category := range parsedModel.SortedRiskCategories() {
		someRisks := parsedModel.SortedRisksOfCategory(category)
		for _, risk := range someRisks {
			parsedModel.GeneratedRisksBySyntheticId[strings.ToLower(risk.SyntheticId)] = risk
		}
	}

	return results
}

// generateRisksSafely executes one rule and converts panics into ordinary execution failures,
// so that one broken rule can never crash the whole analysis run.
func generateRisksSafely(rule types.RiskRule, parsedModel *types.Model) (generatedRisks []*types.Risk, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("risk rule panicked while generating risks: %v", recovered)
		}
	}()
	return rule.GenerateRisks(parsedModel)
}

// validateGeneratedRisk validates one generated risk: owning category, references into the model
// and global synthetic-id uniqueness. Returns a rejected-risk description when invalid, nil otherwise.
func validateGeneratedRisk(ruleId string, risk *types.Risk, parsedModel *types.Model,
	acceptedSyntheticIds map[string]string) *types.RejectedRisk {
	reasons := make([]string, 0)

	rejected := func() *types.RejectedRisk {
		if risk == nil {
			return &types.RejectedRisk{Reasons: []string{"rule returned a nil risk entry"}}
		}
		rejectedRisk := &types.RejectedRisk{
			SyntheticId: risk.SyntheticId,
			Title:       risk.Title,
			Reasons:     reasons,
		}
		return rejectedRisk
	}

	if risk == nil {
		return rejected()
	}

	categoryId := strings.TrimSpace(risk.CategoryId)
	if categoryId == "" {
		reasons = append(reasons, "risk has no category assigned")
	} else if !strings.EqualFold(categoryId, ruleId) {
		reasons = append(reasons, fmt.Sprintf("risk category %q does not match the executing rule id %q", categoryId, ruleId))
	}

	syntheticId := strings.TrimSpace(risk.SyntheticId)
	if syntheticId == "" {
		reasons = append(reasons, "risk has no synthetic id assigned")
	} else if ownerCategory, duplicated := acceptedSyntheticIds[strings.ToLower(syntheticId)]; duplicated {
		reasons = append(reasons, fmt.Sprintf("duplicate synthetic id %q (already generated by risk category %q)", syntheticId, ownerCategory))
	}

	if referenced := strings.TrimSpace(risk.MostRelevantTechnicalAssetId); referenced != "" {
		if _, ok := parsedModel.TechnicalAssets[referenced]; !ok {
			reasons = append(reasons, fmt.Sprintf("risk references missing technical asset %q", referenced))
		}
	}
	if referenced := strings.TrimSpace(risk.MostRelevantDataAssetId); referenced != "" {
		if _, ok := parsedModel.DataAssets[referenced]; !ok {
			reasons = append(reasons, fmt.Sprintf("risk references missing data asset %q", referenced))
		}
	}
	if referenced := strings.TrimSpace(risk.MostRelevantCommunicationLinkId); referenced != "" {
		if _, ok := parsedModel.CommunicationLinks[referenced]; !ok {
			reasons = append(reasons, fmt.Sprintf("risk references missing communication link %q", referenced))
		}
	}
	if referenced := strings.TrimSpace(risk.MostRelevantTrustBoundaryId); referenced != "" {
		if _, ok := parsedModel.TrustBoundaries[referenced]; !ok {
			reasons = append(reasons, fmt.Sprintf("risk references missing trust boundary %q", referenced))
		}
	}
	if referenced := strings.TrimSpace(risk.MostRelevantSharedRuntimeId); referenced != "" {
		if _, ok := parsedModel.SharedRuntimes[referenced]; !ok {
			reasons = append(reasons, fmt.Sprintf("risk references missing shared runtime %q", referenced))
		}
	}
	for _, referenced := range risk.DataBreachTechnicalAssetIDs {
		referenced = strings.TrimSpace(referenced)
		if referenced == "" {
			continue
		}
		if _, ok := parsedModel.TechnicalAssets[referenced]; !ok {
			reasons = append(reasons, fmt.Sprintf("risk data breach path references missing technical asset %q", referenced))
		}
	}

	if len(reasons) > 0 {
		return rejected()
	}
	return nil
}

func writeToFile(name string, item any, filename string, progressReporter types.ProgressReporter) {
	if item == nil {
		return
	}

	if filename == "" {
		return
	}

	exported, exportError := yaml.Marshal(item)
	if exportError != nil {
		progressReporter.Warnf("Unable to export %v: %v", name, exportError)
		return
	}

	_ = os.MkdirAll(filepath.Dir(filename), 0750)

	writeError := os.WriteFile(filename, exported, 0600)
	if writeError != nil {
		progressReporter.Warnf("Unable to write %v to %q: %v", name, filename, writeError)
		return
	}

	progressReporter.Infof("Wrote %v to %q", name, filename)
}
