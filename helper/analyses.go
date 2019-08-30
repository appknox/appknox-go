package helper

import (
	"context"
	"fmt"
	"os"

	"github.com/appknox/appknox-go/appknox"
	"github.com/cheynewallace/tabby"
)

// ProcessAnalyses takes the list of analyses and print it to CLI.
func ProcessAnalyses(fileID int) {
	ctx := context.Background()
	client := getClient()
	_, analysisResponse, err := client.Analyses.ListByFile(ctx, fileID, nil)
	analysisCount := analysisResponse.GetCount()
	options := &appknox.AnalysisListOptions{
		ListOptions: appknox.ListOptions{
			Limit: analysisCount},
	}
	finalAnalyses, _, err := client.Analyses.ListByFile(ctx, fileID, options)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	t := tabby.New()
	t.AddHeader(
		"ID", "RISK", "STATUS", "CVSS-VECTOR",
		"CVSS-BASE", "CVSS-VERSION", "OWASP",
		"UPDATED-ON", "VULNERABILITY-ID")
	for i := 0; i < len(finalAnalyses); i++ {
		t.AddLine(
			finalAnalyses[i].ID,
			finalAnalyses[i].Risk,
			finalAnalyses[i].Status,
			finalAnalyses[i].CvssVector,
			finalAnalyses[i].CvssBase,
			finalAnalyses[i].CvssVersion,
			finalAnalyses[i].Owasp,
			*finalAnalyses[i].UpdatedOn,
			finalAnalyses[i].VulnerabilityID,
		)
	}
	t.Print()
}
