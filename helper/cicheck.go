package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/appknox/enums"
	"github.com/cheynewallace/tabby"
	"github.com/vbauerster/mpb/v4"
	"github.com/vbauerster/mpb/v4/decor"
)

// waitForStaticScan polls the static scan status summary until the static
// scan completes or the budget's static deadline passes. It exits the process on
// failure.
func waitForStaticScan(fileID int, budget ScanBudget) {
	const minTimeout = 1   // 1 minute
	const maxTimeout = 240 // 4 hours

	staticScanTimeout := budget.SastTimeout
	if staticScanTimeout < minTimeout*time.Minute || staticScanTimeout > maxTimeout*time.Minute {
		errMsg := fmt.Sprintf("Error: timeout must be between %v minute and %v minutes", minTimeout, maxTimeout)
		fmt.Println(errMsg) // Print error message to standard output
		os.Exit(1)
	}
	ctx := context.Background()
	client := getClient()
	var staticScanProgess int
	start := budget.Start
	deadline := budget.SastDeadline()
	fmt.Printf("Starting scan at: %v with timeout of %v\n", start.Format(time.RFC3339), staticScanTimeout)
	p := mpb.New(
		mpb.WithWidth(60),
		mpb.WithRefreshRate(180*time.Millisecond),
		mpb.WithOutput(os.Stderr),
	)
	name := "Static Scan Progress: "
	bar := p.AddBar(100, mpb.BarStyle("[=>-|"),
		mpb.PrependDecorators(
			decor.Name(name, decor.WC{W: len(name) + 1, C: decor.DidentRight}),
			decor.Percentage(),
		),
		mpb.AppendDecorators(
			decor.Name("] "),
		),
	)

	for staticScanProgess < 100 {
		summary, _, err := client.Files.GetScansStatusSummary(ctx, fileID)
		if err != nil {
			PrintError(err)
			os.Exit(1)
		}
		staticScanProgess = summary.StaticScanProgress
		bar.SetCurrent(int64(staticScanProgess), time.Since(start))

		if time.Now().After(deadline) {
			err := errors.New("Request timed out")
			PrintError(err)
			os.Exit(1)
		}
		time.Sleep(5 * time.Second)
	}
	// Stop the progress bar's render goroutine so it does not keep redrawing
	// over subsequent output (e.g. the KnoxIQ status lines).
	p.Wait()
}

// CiPolicy describes the active build-failure gates for a CI check. A threshold
// of -1 means that gate is inactive.
type CiPolicy struct {
	RiskThreshold        int
	LikelihoodThreshold  int
	HealthScoreThreshold int
	Budget               ScanBudget
}

// ProcessCiCheck runs the standard risk/likelihood gates, or the KnoxIQ flow
// when the file has KnoxIQ triage.
func ProcessCiCheck(fileID int, policy CiPolicy) {
	waitForStaticScan(fileID, policy.Budget)
	ctx := context.Background()
	client := getClient()

	if _, available := knoxIQAvailable(ctx, client, fileID); available {
		processKnoxIQCiCheck(ctx, client, fileID, policy)
		return
	}
	warnLikelihoodUnavailable(&policy)
	analyses := listAllAnalyses(ctx, client, fileID)
	runStandardRiskCheck(ctx, client, fileID, policy, analyses)
}

func listAllAnalyses(ctx context.Context, client *appknox.Client, fileID int) []*appknox.Analysis {
	_, analysisResponse, err := client.Analyses.ListByFile(ctx, fileID, nil)
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}
	options := &appknox.AnalysisListOptions{
		ListOptions: appknox.ListOptions{Limit: analysisResponse.GetCount()},
	}
	analyses, _, err := client.Analyses.ListByFile(ctx, fileID, options)
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}
	return analyses
}

func filterAnalysesByRisk(analyses []*appknox.Analysis, riskThreshold int) []*appknox.Analysis {
	vulnerable := make([]*appknox.Analysis, 0)
	for _, analysis := range analyses {
		if int(analysis.ComputedRisk) >= riskThreshold {
			vulnerable = append(vulnerable, analysis)
		}
	}
	return vulnerable
}

func printStandardTable(ctx context.Context, client *appknox.Client, analyses []*appknox.Analysis) {
	t := tabby.New()
	t.AddHeader(
		"ANALYSIS-ID", "RISK", "CVSS-VECTOR", "CVSS-BASE",
		"VULNERABILITY-ID", "VULNERABILITY-NAME",
	)
	for _, analysis := range analyses {
		vulnerability, _, err := client.Vulnerabilities.GetByID(ctx, analysis.VulnerabilityID)
		if err != nil {
			PrintError(err)
			os.Exit(1)
		}
		t.AddLine(
			analysis.ID, analysis.ComputedRisk, analysis.CvssVector,
			analysis.CvssBase, analysis.VulnerabilityID, vulnerability.Name,
		)
	}
	t.Print()
}

// printActiveGates prints which build-failure gates are actually in effect,
// so a passing build can't be misread as "everything was checked" when a gate
// silently ended up disabled (e.g. a likelihood gate requested on a file with
// no KnoxIQ triage — see warnLikelihoodUnavailable).
func printActiveGates(policy CiPolicy) {
	var gates []string
	if policy.RiskThreshold >= 0 {
		gates = append(gates, fmt.Sprintf("risk >= %s", enums.RiskType(policy.RiskThreshold)))
	}
	if policy.LikelihoodThreshold >= 0 {
		gates = append(gates, fmt.Sprintf("exploit likelihood >= %s", enums.ExploitabilityType(policy.LikelihoodThreshold)))
	}
	if len(gates) == 0 {
		fmt.Println("\nActive gates: none")
		return
	}
	fmt.Printf("\nActive gates: %s\n", strings.Join(gates, ", "))
}

// decideGates prints the pass/fail summary for the risk and likelihood gates
// and exits non-zero when any active gate is breached.
func decideGates(fileID int, policy CiPolicy, riskCount, likelihoodCount int) {
	printActiveGates(policy)
	msg := fmt.Sprintf("\nCheck file ID %d on appknox dashboard for more details.\n", fileID)
	riskFail := policy.RiskThreshold >= 0 && riskCount > 0
	likelihoodFail := policy.LikelihoodThreshold >= 0 && likelihoodCount > 0
	if riskFail {
		PrintError(fmt.Sprintf("Found %d vulnerabilities with risk >= %s",
			riskCount, enums.RiskType(policy.RiskThreshold)))
	}
	if likelihoodFail {
		PrintError(fmt.Sprintf("Found %d vulnerabilities with exploit likelihood >= %s",
			likelihoodCount, enums.ExploitabilityType(policy.LikelihoodThreshold)))
	}
	if riskFail || likelihoodFail {
		fmt.Print(msg)
		os.Exit(1)
	}
	fmt.Println("\nNo vulnerabilities found breaching the configured thresholds.")
	fmt.Print(msg)
}

func runStandardRiskCheck(ctx context.Context, client *appknox.Client, fileID int, policy CiPolicy, analyses []*appknox.Analysis) {
	riskCount := 0
	if policy.RiskThreshold >= 0 {
		vulnerable := filterAnalysesByRisk(analyses, policy.RiskThreshold)
		riskCount = len(vulnerable)
		if riskCount > 0 {
			printStandardTable(ctx, client, vulnerable)
		}
	}
	decideGates(fileID, policy, riskCount, 0)
}

// ProcessHealthScoreCiCheck gates on the file health score, plus the optional
// exploit-likelihood gate when configured.
func ProcessHealthScoreCiCheck(fileID int, policy CiPolicy) {
	waitForStaticScan(fileID, policy.Budget)
	ctx := context.Background()
	client := getClient()

	options := &appknox.HealthScoreOptions{
		EventType: string(enums.EventTypeSASTCompleted),
	}
	healthScoreResponse, _, err := client.Files.GetHealthScore(ctx, fileID, options)
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}

	likelihoodCount := 0
	if policy.LikelihoodThreshold >= 0 {
		likelihoodCount = countLikelihoodOffenders(ctx, client, fileID, policy)
	}
	decideHealthScore(fileID, policy, healthScoreResponse.HealthScore, likelihoodCount)
}

// decideHealthScore prints the health-score (and optional likelihood) verdict
// and exits non-zero when the score is below threshold or the likelihood gate
// is breached.
func decideHealthScore(fileID int, policy CiPolicy, score, likelihoodCount int) {
	msg := fmt.Sprintf("\nCheck file ID %d on appknox dashboard for more details.\n", fileID)
	healthFail := score < policy.HealthScoreThreshold
	likelihoodFail := policy.LikelihoodThreshold >= 0 && likelihoodCount > 0
	if healthFail {
		PrintError(fmt.Sprintf("Health score %d is below the threshold %d.",
			score, policy.HealthScoreThreshold))
	} else {
		fmt.Printf("\nHealth score %d is greater than or equal to threshold %d.\n",
			score, policy.HealthScoreThreshold)
	}
	if likelihoodFail {
		PrintError(fmt.Sprintf("Found %d vulnerabilities with exploit likelihood >= %s",
			likelihoodCount, enums.ExploitabilityType(policy.LikelihoodThreshold)))
	}
	if healthFail || likelihoodFail {
		fmt.Print(msg)
		os.Exit(1)
	}
	fmt.Println("Build passed.")
	fmt.Print(msg)
}
