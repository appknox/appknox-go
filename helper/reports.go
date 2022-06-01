package helper

import (
	"context"
	"errors"
	"fmt"
)

func ProcessDownloadReports(fileID int, alwaysApproved bool, output string) (bool, error) {
	fmt.Println("Warning: This process will download report file to system.")
	if !alwaysApproved {
		fmt.Println("Please pass `--always-approved` to approve all the reports")
		return false, errors.New("Please pass `--always-approved` to approve all the reports")
	}

	ctx := context.Background()
	client := getClient()

	report, err := client.Reports.GetReportURL(ctx, fileID)
	if err != nil {
		PrintError(err)
		return false, err
	}
	if report == nil {
		PrintError(errors.New("No report found"))
		return false, errors.New("No report found")
	}

	out, err := client.Reports.DownloadFile(ctx, report.URL, output)
	if err != nil {
		PrintError(err)
		return false, err
	}

	fmt.Println("Report downloaded successfully.")
	fmt.Println("Report saved to: ", out)
	return true, nil
}
