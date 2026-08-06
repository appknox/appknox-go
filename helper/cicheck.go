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

// ProcessCiCheck takes the list of analyses and print it to CLI.
func ProcessCiCheck(fileID, riskThreshold int, staticScanTimeout time.Duration) {
	// Add timeout validation
	const minTimeout=1;//1 minute
	const maxTimeout=240;//4 hours

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

	_, analysisResponse, err := client.Analyses.ListByFile(ctx, fileID, nil)
	analysisCount := analysisResponse.GetCount()
	options := &appknox.AnalysisListOptions{
		ListOptions: appknox.ListOptions{
			Limit: analysisCount},
	}
	finalAnalyses, _, err := client.Analyses.ListByFile(ctx, fileID, options)
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}
	t := tabby.New()
	t.AddHeader(
		"ANALYSIS-ID",
		"RISK",
		"CVSS-VECTOR",
		"CVSS-BASE",
		"VULNERABILITY-ID",
		"VULNERABILITY-NAME",
	)
	vulnerableAnalyses := make([]appknox.Analysis, 0)
	for _, analysis := range finalAnalyses {
		if int(analysis.ComputedRisk) >= riskThreshold {
			vulnerableAnalyses = append(vulnerableAnalyses, *analysis)
		}
	}
	for _, analysis := range vulnerableAnalyses {
		vulnerability, _, err := client.Vulnerabilities.GetByID(
			ctx, analysis.VulnerabilityID,
		)
		if err != nil {
			PrintError(err)
			os.Exit(1)
		}
		t.AddLine(
			analysis.ID,
			analysis.ComputedRisk,
			analysis.CvssVector,
			analysis.CvssBase,
			analysis.VulnerabilityID,
			vulnerability.Name,
		)
	}
	vulLen := len(vulnerableAnalyses)
	msg := fmt.Sprintf("\nCheck file ID %d on appknox dashboard for more details.\n", fileID)
	if vulLen > 0 {
		errmsg := fmt.Sprintf("Found %d vulnerabilities with risk >= %s\n", vulLen, enums.RiskType(riskThreshold))
		PrintError(errmsg)
		t.Print()
		fmt.Print(msg)
		os.Exit(1)
	} else {
		fmt.Println("\nNo vulnerabilities found with risk threshold >= ", enums.RiskType(riskThreshold))
		fmt.Print(msg)
	}
}
