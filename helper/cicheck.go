package helper

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/appknox/enums"
	"github.com/cheynewallace/tabby"
	"github.com/vbauerster/mpb/v4"
	"github.com/vbauerster/mpb/v4/decor"
)

// ProcessCiCheck takes the list of analyses and print it to CLI.
func ProcessCiCheck(fileID, riskThreshold int) {
	ctx := context.Background()
	client := getClient()
	var staticScanProgess int
	start := time.Now()
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
		file, _, err := client.Files.GetByID(ctx, fileID)
		if err != nil {
			PrintError(err)
			os.Exit(1)
		}
		staticScanProgess = file.StaticScanProgress
		bar.SetCurrent(int64(staticScanProgess), time.Since(start))
		if time.Since(start) > 15*time.Minute {
			err := errors.New("Request timed out")
			PrintError(err)
			os.Exit(1)
		}
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
	var foundVulnerability bool
	t := tabby.New()
	t.AddHeader(
		"ID", "RISK", "CVSS-VECTOR",
		"CVSS-BASE", "VULNERABILITY-ID",
		"VULNERABILITY-NAME")
	for i := 0; i < len(finalAnalyses); i++ {
		if int(finalAnalyses[i].Risk) >= riskThreshold {
			foundVulnerability = true
			vulnerabilityID := finalAnalyses[i].VulnerabilityID
			vulnerability, _, err := client.Vulnerabilities.GetByID(ctx, vulnerabilityID)
			if err != nil {
				PrintError(err)
				os.Exit(1)
			}
			t.AddLine(
				finalAnalyses[i].ID,
				finalAnalyses[i].Risk,
				finalAnalyses[i].CvssVector,
				finalAnalyses[i].CvssBase,
				vulnerabilityID,
				vulnerability.Name,
			)
		}
	}
	if foundVulnerability {
		PrintError(
			"Found vulnerabilities with risk threshold greater or equal than the provided:", enums.RiskType(riskThreshold))
		PrintError("")
		t.Print()
		PrintError("")
		os.Exit(1)
	} else {
		PrintError(
			"No vulnerabilities found with risk threshold greater or equal than the provided:", enums.RiskType(riskThreshold))
	}
}
