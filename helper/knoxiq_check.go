package helper

import (
	"context"
	"fmt"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/appknox/enums"
	"github.com/cheynewallace/tabby"
	"github.com/spf13/viper"
)

const (
	knoxIQPollInterval = 5 * time.Second
	knoxIQPollTimeout  = 30 * time.Minute
)

// processKnoxIQCiCheck shows intermediary SAST results, waits for triage, then
// gates on the triaged results, falling back to SAST results if KnoxIQ does
// not complete.
func processKnoxIQCiCheck(ctx context.Context, client *appknox.Client, fileID, riskThreshold int) {
	analyses := listAllAnalyses(ctx, client, fileID)
	intermediate := filterAnalysesByRisk(analyses, riskThreshold)
	fmt.Println("\nIntermediary results (before KnoxIQ triage):")
	if len(intermediate) > 0 {
		printStandardTable(ctx, client, intermediate)
	} else {
		fmt.Println("No SAST vulnerabilities at or above the risk threshold.")
	}

	if !waitForKnoxIQ(ctx, client, fileID) {
		fmt.Println("\nKnoxIQ did not complete; falling back to SAST results for the build decision.")
		riskDecision(fileID, len(intermediate), riskThreshold)
		return
	}

	triaged, err := listAllCICDAnalyses(ctx, client, fileID)
	if err != nil {
		fmt.Printf("\n%s\nFalling back to SAST results for the build decision.\n", err.Error())
		riskDecision(fileID, len(intermediate), riskThreshold)
		return
	}
	reportKnoxIQGate(fileID, riskThreshold, triaged)
}

// waitForKnoxIQ polls the scan status and returns true only when triage
// completes; false on error, a terminal non-running state, or timeout.
func waitForKnoxIQ(ctx context.Context, client *appknox.Client, fileID int) bool {
	start := time.Now()
	lastStatus := enums.KnoxIQScanStatusType(-99)
	fmt.Println("\nKnoxIQ triage status:")
	for {
		scanStatus, _, err := client.KnoxIQ.GetScanStatus(ctx, fileID)
		if err != nil {
			PrintError(err)
			return false
		}
		status := enums.KnoxIQScanStatusType(scanStatus.SastStatus)
		if status != lastStatus {
			fmt.Printf("  %s\n", status)
			lastStatus = status
		}
		switch status {
		case enums.KnoxIQStatusCompleted:
			return true
		case enums.KnoxIQStatusErrored,
			enums.KnoxIQStatusDisabled,
			enums.KnoxIQStatusLegacy:
			return false
		}
		if time.Since(start) > knoxIQPollTimeout {
			fmt.Println("  KnoxIQ timed out.")
			return false
		}
		time.Sleep(knoxIQPollInterval)
	}
}

func listAllCICDAnalyses(ctx context.Context, client *appknox.Client, fileID int) ([]*appknox.KnoxIQCICDAnalysis, error) {
	_, resp, err := client.KnoxIQ.ListCICDAnalyses(ctx, fileID, nil)
	if err != nil {
		return nil, err
	}
	options := &appknox.AnalysisListOptions{
		ListOptions: appknox.ListOptions{Limit: resp.Count},
	}
	results, _, err := client.KnoxIQ.ListCICDAnalyses(ctx, fileID, options)
	if err != nil {
		return nil, err
	}
	return results, nil
}

// partitionNeedsReview splits rows into those that count towards the build
// decision and those excluded as needs-review; include=true excludes nothing.
func partitionNeedsReview(rows []*appknox.KnoxIQCICDAnalysis, include bool) (counted, needsReview []*appknox.KnoxIQCICDAnalysis) {
	for _, row := range rows {
		if row.NeedsReview && !include {
			needsReview = append(needsReview, row)
		} else {
			counted = append(counted, row)
		}
	}
	return counted, needsReview
}

func filterCICDByRisk(rows []*appknox.KnoxIQCICDAnalysis, riskThreshold int) []*appknox.KnoxIQCICDAnalysis {
	vulnerable := make([]*appknox.KnoxIQCICDAnalysis, 0)
	for _, row := range rows {
		if int(row.ComputedRisk) >= riskThreshold {
			vulnerable = append(vulnerable, row)
		}
	}
	return vulnerable
}

func aeisString(score *float64) string {
	if score == nil {
		return "N/A"
	}
	return fmt.Sprintf("%.1f", *score)
}

func likelihoodString(likelihood *enums.ExploitabilityType) string {
	if likelihood == nil {
		return "N/A"
	}
	return likelihood.String()
}

func printKnoxIQTable(rows []*appknox.KnoxIQCICDAnalysis) {
	t := tabby.New()
	t.AddHeader(
		"ANALYSIS-ID", "RISK", "CVSS-BASE", "VULNERABILITY-ID",
		"VULNERABILITY-NAME", "AEIS-SCORE", "EXPLOIT-LIKELIHOOD",
	)
	for _, row := range rows {
		t.AddLine(
			row.ID, row.ComputedRisk, row.CvssBase, row.VulnerabilityID,
			row.VulnerabilityName, aeisString(row.ExploitabilityScore),
			likelihoodString(row.ExploitabilityLikelihood),
		)
	}
	t.Print()
}

func reportKnoxIQGate(fileID, riskThreshold int, triaged []*appknox.KnoxIQCICDAnalysis) {
	counted, needsReview := partitionNeedsReview(
		triaged, viper.GetBool("include-needs-review"))
	vulnerable := filterCICDByRisk(counted, riskThreshold)

	fmt.Println("\nFinal triaged results:")
	if len(vulnerable) > 0 {
		printKnoxIQTable(vulnerable)
	}
	if len(needsReview) > 0 {
		fmt.Println("\nNeeds review (excluded from build decision):")
		printKnoxIQTable(needsReview)
	}
	riskDecision(fileID, len(vulnerable), riskThreshold)
}
