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

const knoxIQPollInterval = 5 * time.Second

// knoxIQAvailable reports the KnoxIQ SAST state for a file and whether there is
// triage worth surfacing — i.e. results exist or are on their way. It asks "does
// this file have KnoxIQ?" rather than "will KnoxIQ auto-run?", so files whose
// triage was started manually are included.
//
// 403 (org without the KnoxIQ feature) and 404 (backend without the KnoxIQ
// endpoints) both mean "not available", so the CLI silently falls back to the
// plain SAST flow. Anything else is surfaced before falling back.
func knoxIQAvailable(
	ctx context.Context, client *appknox.Client, fileID int,
) (enums.KnoxIQScanStatusType, bool) {
	scanStatus, _, err := client.KnoxIQ.GetScanStatus(ctx, fileID)
	if err != nil {
		switch appknox.StatusCodeOf(err) {
		case 403, 404:
			// Expected for non-KnoxIQ orgs and older backends.
		default:
			PrintError(err)
		}
		return enums.KnoxIQStatusDisabled, false
	}
	status := enums.KnoxIQScanStatusType(scanStatus.SastStatus)
	switch status {
	case enums.KnoxIQStatusPending,
		enums.KnoxIQStatusRunning,
		enums.KnoxIQStatusCompleted:
		return status, true
	}
	return status, false
}

// processKnoxIQCiCheck shows intermediary SAST results, waits for triage, then
// gates on the triaged results, falling back to SAST results if KnoxIQ does
// not complete.
func processKnoxIQCiCheck(ctx context.Context, client *appknox.Client, fileID int, policy CiPolicy) {
	analyses := listAllAnalyses(ctx, client, fileID)
	displayThreshold := policy.RiskThreshold
	if displayThreshold < 0 {
		displayThreshold = int(enums.Risk.Low)
	}
	intermediate := filterAnalysesByRisk(analyses, displayThreshold)
	fmt.Println("\nIntermediary results (before KnoxIQ triage):")
	if len(intermediate) > 0 {
		printStandardTable(ctx, client, intermediate)
	} else {
		fmt.Println("No SAST vulnerabilities at or above the threshold.")
	}

	if !waitForKnoxIQ(ctx, client, fileID, policy.Budget.KnoxIQDeadline()) {
		fmt.Println("\nKnoxIQ did not complete; falling back to SAST results for the build decision.")
		decideOnSASTFallback(fileID, policy, analyses)
		return
	}

	triaged, err := listAllCICDAnalyses(ctx, client, fileID)
	if err != nil {
		fmt.Printf("\n%s\nFalling back to SAST results for the build decision.\n", err.Error())
		decideOnSASTFallback(fileID, policy, analyses)
		return
	}
	reportKnoxIQGate(fileID, policy, triaged)
}

// decideOnSASTFallback gates on SAST risk only, used when KnoxIQ triage is
// unavailable. The likelihood gate is skipped (with a warning) since there is
// no triage data.
func decideOnSASTFallback(fileID int, policy CiPolicy, analyses []*appknox.Analysis) {
	if policy.LikelihoodThreshold >= 0 {
		PrintError("exploit-likelihood gate skipped — KnoxIQ triage unavailable")
	}
	riskCount := 0
	if policy.RiskThreshold >= 0 {
		riskCount = len(filterAnalysesByRisk(analyses, policy.RiskThreshold))
	}
	decideGates(fileID, policy, riskCount, 0)
}

// waitForKnoxIQ polls the scan status until the given deadline and returns true
// only when triage completes; false on error, a terminal non-running state, or
// when the deadline passes. Takes an absolute deadline rather than a duration so
// the caller's budget (which carries over unused static-scan time) is respected.
func waitForKnoxIQ(ctx context.Context, client *appknox.Client, fileID int, deadline time.Time) bool {
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
		if time.Now().After(deadline) {
			fmt.Println("  KnoxIQ timed out.")
			return false
		}
		time.Sleep(knoxIQPollInterval)
	}
}

// countLikelihoodOffenders waits for KnoxIQ triage and returns how many counted
// analyses meet the likelihood threshold; 0 (with a warning) when the file has
// no KnoxIQ triage.
func countLikelihoodOffenders(ctx context.Context, client *appknox.Client, fileID int, policy CiPolicy) int {
	if _, available := knoxIQAvailable(ctx, client, fileID); !available {
		PrintError("exploit-likelihood gating requires KnoxIQ triage — skipping (no KnoxIQ results for this file)")
		return 0
	}
	if !waitForKnoxIQ(ctx, client, fileID, policy.Budget.KnoxIQDeadline()) {
		PrintError("KnoxIQ did not complete — skipping exploit-likelihood gate")
		return 0
	}
	triaged, err := listAllCICDAnalyses(ctx, client, fileID)
	if err != nil {
		PrintError("Could not fetch KnoxIQ results — skipping exploit-likelihood gate")
		return 0
	}
	counted, _ := partitionNeedsReview(triaged, viper.GetBool("include-needs-review"))
	return len(filterCICDByLikelihood(counted, policy.LikelihoodThreshold))
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

func filterCICDByLikelihood(rows []*appknox.KnoxIQCICDAnalysis, threshold int) []*appknox.KnoxIQCICDAnalysis {
	vulnerable := make([]*appknox.KnoxIQCICDAnalysis, 0)
	for _, row := range rows {
		if row.ExploitabilityLikelihood != nil && int(*row.ExploitabilityLikelihood) >= threshold {
			vulnerable = append(vulnerable, row)
		}
	}
	return vulnerable
}

// unionCICD merges two row slices, de-duplicating by analysis ID.
func unionCICD(groups ...[]*appknox.KnoxIQCICDAnalysis) []*appknox.KnoxIQCICDAnalysis {
	seen := make(map[int]bool)
	out := make([]*appknox.KnoxIQCICDAnalysis, 0)
	for _, group := range groups {
		for _, row := range group {
			if !seen[row.ID] {
				seen[row.ID] = true
				out = append(out, row)
			}
		}
	}
	return out
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

func reportKnoxIQGate(fileID int, policy CiPolicy, triaged []*appknox.KnoxIQCICDAnalysis) {
	counted, needsReview := partitionNeedsReview(
		triaged, viper.GetBool("include-needs-review"))

	var riskVulns, likelihoodVulns []*appknox.KnoxIQCICDAnalysis
	if policy.RiskThreshold >= 0 {
		riskVulns = filterCICDByRisk(counted, policy.RiskThreshold)
	}
	if policy.LikelihoodThreshold >= 0 {
		likelihoodVulns = filterCICDByLikelihood(counted, policy.LikelihoodThreshold)
	}

	offending := unionCICD(riskVulns, likelihoodVulns)
	fmt.Println("\nFinal triaged results:")
	if len(offending) > 0 {
		printKnoxIQTable(offending)
	}
	if len(needsReview) > 0 {
		fmt.Println("\nNeeds review (excluded from build decision):")
		printKnoxIQTable(needsReview)
	}
	decideGates(fileID, policy, len(riskVulns), len(likelihoodVulns))
}
