package model

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

type CustomRiskCategory struct {
	types.RiskCategory `json:"risk_category" yaml:"risk_category,omitempty"`

	Tags   []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	runner *runner
}

func (what *CustomRiskCategory) Init(category *types.RiskCategory, tags []string) *CustomRiskCategory {
	*what = CustomRiskCategory{
		RiskCategory: *category,
		Tags:         tags,
	}

	return what
}

func (what *CustomRiskCategory) Category() *types.RiskCategory {
	return &what.RiskCategory
}

func (what *CustomRiskCategory) SupportedTags() []string {
	return what.Tags
}

// RuleOrigin marks this rule as provided by an external executable plugin.
func (what *CustomRiskCategory) RuleOrigin() string {
	return types.ExternalRuleOrigin
}

func (what *CustomRiskCategory) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	if what.runner == nil {
		return nil, fmt.Errorf("custom risk rule %q has no executable runner", what.RiskCategory.ID)
	}

	generatedRisks := make([]*types.Risk, 0)
	runError := what.runner.Run(parsedModel, &generatedRisks, "-generate-risks")
	if runError != nil {
		return nil, fmt.Errorf("failed to generate risks for custom risk rule %q: %w", what.runner.Filename, runError)
	}

	return generatedRisks, nil
}

// LoadCustomRiskRules loads external executable risk rule plugins.
// Rules that cannot be loaded or fail to report their category info are not inserted
// into the returned rule set; instead they are reported as failed rule execution
// results so that strict analysis aborts and partial analysis can mark the gap.
func LoadCustomRiskRules(pluginDir string, pluginFiles []string, reporter types.ProgressReporter) (types.RiskRules, types.RuleExecutionResults) {
	customRiskRuleList := make([]string, 0)
	customRiskRules := make(types.RiskRules)
	loadResults := make(types.RuleExecutionResults, 0)
	if len(pluginFiles) > 0 {
		reporter.Info("Loading custom risk rules:", strings.Join(pluginFiles, ", "))

		for _, pluginFile := range pluginFiles {
			if len(pluginFile) == 0 {
				continue
			}

			loadResult := &types.RuleExecutionResult{
				RuleID:     pluginFile,
				RuleOrigin: types.ExternalRuleOrigin,
				Status:     types.RuleFailed,
			}

			newRunner, loadError := new(runner).Load(filepath.Join(pluginDir, pluginFile))
			if loadError != nil {
				loadResult.Message = fmt.Sprintf("custom risk rule %q not loaded: %v", pluginFile, loadError)
				reporter.Warnf("%v", loadResult.Message)
				loadResults = append(loadResults, loadResult)
				continue
			}

			risk := new(CustomRiskCategory)
			runError := newRunner.Run(nil, &risk, "-get-info")
			if runError != nil {
				loadResult.Message = fmt.Sprintf("failed to get info for custom risk rule %q: %v", pluginFile, runError)
				reporter.Warnf("%v", loadResult.Message)
				loadResults = append(loadResults, loadResult)
				continue
			}

			if strings.TrimSpace(risk.ID) == "" {
				loadResult.Message = fmt.Sprintf("custom risk rule %q returned an empty risk category id", pluginFile)
				reporter.Warnf("%v", loadResult.Message)
				loadResults = append(loadResults, loadResult)
				continue
			}

			risk.runner = newRunner
			loadResult.RuleID = risk.ID
			customRiskRules[risk.ID] = risk
			customRiskRuleList = append(customRiskRuleList, risk.ID)
			reporter.Info("Custom risk rule loaded:", risk.ID)
		}

		reporter.Info("Loaded custom risk rules:", strings.Join(customRiskRuleList, ", "))
	}

	return customRiskRules, loadResults
}
