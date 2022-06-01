package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
)

func ProcessDownloadReports(fileID int, alwaysApproved bool, output string) {
	fmt.Println("Warning: This process will download report file to system.")
	if !alwaysApproved {
		fmt.Println("Please pass `--always-approved` to approve all the reports")
		os.Exit(1)
	}

	ctx := context.Background()
	client := getClient()

	report, err := client.Reports.GetReportURL(ctx, fileID)
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}
	if report == nil {
		PrintError(errors.New("No report found"))
		os.Exit(1)
	}

	out, err := client.Reports.DownloadFile(ctx, report.URL, output)
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}

	fmt.Println("Report downloaded successfully.")
	fmt.Println("Report saved to: ", out)
}
