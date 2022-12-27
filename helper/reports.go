package helper

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cheynewallace/tabby"
)

func ProcessListReports(fileID int) error {
	ctx := context.Background()
	client := getClient()
	reports, err := client.Reports.List(ctx, fileID)
	if err != nil {
		return err
	}
	t := tabby.New()
	header := []interface{}{
		"ID",
		"Generated On",
		"Language",
		"Progress",
		"Rating",
		"Show API Scan",
		"Show Manual Scan",
		"Show Static Scan",
		"Show Dynamic Scan",
		"Show Ignored Analyses Scan",
		"Show HIPAA",
		"Is HIPAA Inherited",
		"Show PCIDSS",
		"Is PCIDSS Inherited",
	}
	t.AddHeader(header...)
	for i := 0; i < len(reports); i++ {
		row := []interface{}{
			reports[i].ID,
			reports[i].GeneratedOn.Format(time.RFC1123),
			reports[i].Language,
			reports[i].Progress,
			reports[i].Rating,
			reports[i].ReportPreferences.ShowAPIScan,
			reports[i].ReportPreferences.ShowManualScan,
			reports[i].ReportPreferences.ShowStaticScan,
			reports[i].ReportPreferences.ShowDynamicScan,
			reports[i].ReportPreferences.ShowIgnoredAnalyses,
			reports[i].ReportPreferences.HIPAAPreferences.ShowHIPPA,
			reports[i].ReportPreferences.HIPAAPreferences.IsInherited,
			reports[i].ReportPreferences.PCIDSSPreferences.ShowPCIDSS,
			reports[i].ReportPreferences.PCIDSSPreferences.IsInherited,
		}
		t.AddLine(row...)
	}
	t.Print()
	return nil

}

func ProcessDownloadReportCSV(reportID int, outputFilePath string) error {
	ctx := context.Background()
	client := getClient()
	downloadUrl, err := client.Reports.GetDownloadUrlCSV(ctx, reportID)
	if err != nil {
		return err
	}

	resp, err := client.Reports.DownloadReportData(ctx, downloadUrl)
	if err != nil {
		return err
	}
	if outputFilePath != "" {
		_, err := client.Reports.WriteReportDataToFile(resp.Body, outputFilePath)
		if err != nil {
			return errors.New(fmt.Sprintf("Failed to download report. Error: %v", err))
		}
	}
	err = client.Reports.WriteReportDataToTerminal(resp)
	return err

}
