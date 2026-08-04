package helper

import (
	"context"
	"fmt"
	"os"

	"github.com/appknox/appknox-go/appknox"
	"github.com/spf13/viper"
)

// ConvertToSARIFReport generates a SARIF report for fileID and writes it to
// filePath.
func ConvertToSARIFReport(fileID int, riskThreshold int, filePath string, budget ScanBudget) error {
	sarif, err := generateSARIF(fileID, riskThreshold, budget)
	if err != nil {
		return err
	}
	sarifContent, err := appknox.GenerateSARIFFileContent(sarif)
	if err != nil {
		return err
	}
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write([]byte(sarifContent)); err != nil {
		return err
	}
	fmt.Println("SARIF report created successfully at:", filePath)
	return nil
}

// generateSARIF mirrors cicheck: waits on the shared scan budget for the
// static scan, then — if the file has KnoxIQ triage — waits for it and
// decorates results with AEIS score / exploit likelihood, filtering out
// needs-review findings (Req 2/3 parity). SARIF is a report generator, not a
// gate, so KnoxIQ not completing in time falls back to plain SAST results
// rather than failing the command.
func generateSARIF(fileID, riskThreshold int, budget ScanBudget) (appknox.SARIF, error) {
	waitForStaticScan(fileID, budget)
	ctx := context.Background()
	client := getClient()

	analyses := listAllAnalyses(ctx, client, fileID)
	properties, excluded := knoxIQSARIFOverlay(ctx, client, fileID, budget)
	filtered := filterAnalysesForSARIF(analyses, riskThreshold, excluded)
	return appknox.BuildSARIF(ctx, client, filtered, properties)
}

// knoxIQSARIFOverlay waits for KnoxIQ triage (if the file has any) and
// returns per-analysis SARIF properties plus the set of analysis IDs to
// exclude as needs-review. Both are empty when the file has no KnoxIQ triage
// or it doesn't complete within the budget.
func knoxIQSARIFOverlay(
	ctx context.Context, client *appknox.Client, fileID int, budget ScanBudget,
) (properties map[int]*appknox.ResultProperties, excluded map[int]bool) {
	properties = map[int]*appknox.ResultProperties{}
	excluded = map[int]bool{}

	if _, available := knoxIQAvailable(ctx, client, fileID); !available {
		return properties, excluded
	}
	if !waitForKnoxIQ(ctx, client, fileID, budget.KnoxIQDeadline()) {
		fmt.Println("\nKnoxIQ did not complete; SARIF will use SAST results only.")
		return properties, excluded
	}
	triaged, err := listAllCICDAnalyses(ctx, client, fileID)
	if err != nil {
		fmt.Printf("\n%s\nSARIF will use SAST results only.\n", err.Error())
		return properties, excluded
	}

	_, needsReview := partitionNeedsReview(triaged, viper.GetBool("include-needs-review"))
	for _, row := range needsReview {
		excluded[row.ID] = true
	}
	for _, row := range triaged {
		if props := sarifPropertiesFor(row); props != nil {
			properties[row.ID] = props
		}
	}
	return properties, excluded
}

// sarifPropertiesFor converts a triaged row to SARIF result properties, or
// nil when the row has neither an AEIS score nor an exploit likelihood yet.
func sarifPropertiesFor(row *appknox.KnoxIQCICDAnalysis) *appknox.ResultProperties {
	if row.ExploitabilityScore == nil && row.ExploitabilityLikelihood == nil {
		return nil
	}
	likelihood := ""
	if row.ExploitabilityLikelihood != nil {
		likelihood = row.ExploitabilityLikelihood.String()
	}
	return &appknox.ResultProperties{
		AEISScore:         row.ExploitabilityScore,
		ExploitLikelihood: likelihood,
	}
}

// filterAnalysesForSARIF applies the risk threshold and drops any analysis
// excluded as KnoxIQ needs-review.
func filterAnalysesForSARIF(analyses []*appknox.Analysis, riskThreshold int, excluded map[int]bool) []*appknox.Analysis {
	filtered := make([]*appknox.Analysis, 0)
	for _, a := range analyses {
		if excluded[a.ID] {
			continue
		}
		if int(a.ComputedRisk) >= riskThreshold {
			filtered = append(filtered, a)
		}
	}
	return filtered
}
