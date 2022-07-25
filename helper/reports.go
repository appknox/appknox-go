package helper

import (
	"context"
	"errors"
	"fmt"
	"time"
)

func ProcessDownloadReports(fileID int, alwaysApproved bool, generate bool, output string) (bool, error) {
	var resultID int

	fmt.Println("Warning: This process will download report file to system.")
	if !alwaysApproved {
		fmt.Println("Please pass `--always-approved` to approve all the reports")
		return false, errors.New("Please pass `--always-approved` to approve all the reports")
	}

	ctx := context.Background()
	client := getClient()

	if generate {
		// This part of code is to generate reports
		fmt.Println("Generating reports...")
		result, err := client.Reports.GenerateReport(ctx, fileID)
		if err != nil {
			PrintError(err)
			return false, err
		}

		// Assigning result id for later use in download report section
		resultID = result.ID
		for result.Progress < 100 {
			time.Sleep(100 * time.Millisecond)
			result, err = client.Reports.FetchReportResult(ctx, resultID)
			if err != nil {
				PrintError(errors.New("Faild to fetch report result"))
				return false, err
			}
			fmt.Printf("\rGeneration progress: %d%%", result.Progress)
		}
		fmt.Println("\nReport generated successfully.")
	} else {
		// This part of code will be executed when user want to download report which is already generated.
		fmt.Println("Fetching reports...")
		result, err := client.Reports.FetchLastReportResult(ctx, fileID)
		if err != nil {
			PrintError(errors.New("No report generated for this file."))
			return false, err
		}
		// Assigning result id for later use in download report section
		resultID = result.ID
	}

	report, err := client.Reports.GetReportURL(ctx, resultID)
	if err != nil {
		PrintError(err)
		return false, err
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
