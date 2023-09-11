package helper

import (
	"context"
	"os"

	"github.com/appknox/appknox-go/appknox"
	"github.com/cheynewallace/tabby"
)

// ProcessAnalyses takes the list of analyses and print it to CLI.
func ProcessAnalyses(fileID int) {
	ctx := context.Background()
	client := getClient()
	_, analysisResponse, err := client.Analyses.ListByFile(ctx, fileID, nil)
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}
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
	profileReportPref, _, err := client.ProjectProfiles.GetProjectProfileReportPreference(ctx, fileID)
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}
	t := tabby.New()
	// header is an interface because t.AddHeader only supports
	// interface elements
	header := []interface{}{"ID", "RISK", "STATUS", "CVSS-VECTOR", "CVSS-BASE", "CVSS-VERSION", "OWASP", "ASVS", "CWE",
		"MSTG", "OWASP API 2023", "OWASP MASVS (v2)"}
	if profileReportPref.ShowPcidss.Value {
		header = append(header, "PCI-DSS")
	}
	if profileReportPref.ShowHipaa.Value {
		header = append(header, "HIPAA")
	}
	if profileReportPref.ShowGdpr.Value {
		header = append(header, "GDPR")
	}
	header = append(header, "UPDATED-ON", "VULNERABILITY-ID")
	t.AddHeader(header...)
	for i := 0; i < len(finalAnalyses); i++ {
		// row is an interface because of two reasons:
		// 1. The elements data types are different
		// 2. t.AddLine only supports interface elements
		row := []interface{}{finalAnalyses[i].ID,
			finalAnalyses[i].ComputedRisk,
			finalAnalyses[i].Status,
			finalAnalyses[i].CvssVector,
			finalAnalyses[i].CvssBase,
			finalAnalyses[i].CvssVersion,
			finalAnalyses[i].Owasp,
			finalAnalyses[i].Asvs,
			finalAnalyses[i].Cwe,
			finalAnalyses[i].Mstg,
			finalAnalyses[i].Owaspapi2023,
			finalAnalyses[i].Masvs,
		}
		if profileReportPref.ShowPcidss.Value {
			row = append(row, finalAnalyses[i].Pcidss)
		}
		if profileReportPref.ShowHipaa.Value {
			row = append(row, finalAnalyses[i].Hipaa)
		}
		if profileReportPref.ShowGdpr.Value {
			row = append(row, finalAnalyses[i].Gdpr)
		}
		row = append(row, *finalAnalyses[i].UpdatedOn,
			finalAnalyses[i].VulnerabilityID)
		t.AddLine(row...)
	}
	t.Print()
}
