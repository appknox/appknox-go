package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/appknox/enums"
	"github.com/cheynewallace/tabby"
	"github.com/vbauerster/mpb/v4"
	"github.com/vbauerster/mpb/v4/decor"
)

// waitForStaticScan polls the static scan status summary until the static
// scan completes or the timeout is reached. It exits the process on failure.
func waitForStaticScan(fileID int, staticScanTimeout time.Duration) {
	const minTimeout = 1   // 1 minute
	const maxTimeout = 240 // 4 hours

	if staticScanTimeout < minTimeout*time.Minute || staticScanTimeout > maxTimeout*time.Minute {
		errMsg := fmt.Sprintf("Error: timeout must be between %v minute and %v minutes", minTimeout, maxTimeout)
		fmt.Println(errMsg) // Print error message to standard output
		os.Exit(1)
	}
	ctx := context.Background()
	client := getClient()
	var staticScanProgess int
	start := time.Now()
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

		if time.Since(start) > staticScanTimeout {
			err := errors.New("Request timed out")
			PrintError(err)
			os.Exit(1)
		}
		time.Sleep(5 * time.Second)
	}
}

// ProcessCiCheck runs the standard risk gate, or the KnoxIQ flow when KnoxIQ
// auto-runs for the file.
func ProcessCiCheck(fileID, riskThreshold int, staticScanTimeout time.Duration) {
	waitForStaticScan(fileID, staticScanTimeout)
	ctx := context.Background()
	client := getClient()

	file, _, err := client.Files.GetByIDV3(ctx, fileID)
	if err == nil && file.IsKnoxIQAutomated {
		processKnoxIQCiCheck(ctx, client, fileID, riskThreshold)
		return
	}
	analyses := listAllAnalyses(ctx, client, fileID)
	runStandardRiskCheck(ctx, client, fileID, riskThreshold, analyses)
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

// riskDecision prints the pass/fail summary and exits non-zero when any
// vulnerability met the threshold.
func riskDecision(fileID, vulnCount, riskThreshold int) {
	msg := fmt.Sprintf("\nCheck file ID %d on appknox dashboard for more details.\n", fileID)
	if vulnCount > 0 {
		PrintError(fmt.Sprintf(
			"Found %d vulnerabilities with risk >= %s\n",
			vulnCount, enums.RiskType(riskThreshold)))
		fmt.Print(msg)
		os.Exit(1)
	}
	fmt.Println("\nNo vulnerabilities found with risk threshold >= ", enums.RiskType(riskThreshold))
	fmt.Print(msg)
}

func runStandardRiskCheck(ctx context.Context, client *appknox.Client, fileID, riskThreshold int, analyses []*appknox.Analysis) {
	vulnerable := filterAnalysesByRisk(analyses, riskThreshold)
	if len(vulnerable) > 0 {
		printStandardTable(ctx, client, vulnerable)
	}
	riskDecision(fileID, len(vulnerable), riskThreshold)
}

// ProcessHealthScoreCiCheck waits for the static scan to complete and then
// compares the file's health score against the provided threshold. The build
// passes if the score is greater than or equal to the threshold.
func ProcessHealthScoreCiCheck(fileID, healthScoreThreshold int, staticScanTimeout time.Duration) {
	waitForStaticScan(fileID, staticScanTimeout)
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

	score := healthScoreResponse.HealthScore
	msg := fmt.Sprintf("\nCheck file ID %d on appknox dashboard for more details.\n", fileID)
	if score >= healthScoreThreshold {
		fmt.Printf("\nHealth score %d is greater than or equal to threshold %d. Build passed.\n", score, healthScoreThreshold)
		fmt.Printf(msg)
	} else {
		errmsg := fmt.Sprintf("Health score %d is below the threshold %d. Build failed.\n", score, healthScoreThreshold)
		PrintError(errmsg)
		fmt.Printf(msg)
		os.Exit(1)
	}
}
