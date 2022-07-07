package helper

import (
	"context"
	"errors"
	"fmt"
	"time"
)

func ProcessDownloadReports(fileID int, alwaysApproved bool, generate string, output string) (bool, error) {
	fmt.Println("Warning: This process will download report file to system.")
	if !alwaysApproved {
		fmt.Println("Please pass `--always-approved` to approve all the reports")
		return false, errors.New("Please pass `--always-approved` to approve all the reports")
	}

	ctx := context.Background()
	client := getClient()

	if generate == "yes" {
		fmt.Println("Generating reports...")
		result, err := client.Reports.GenerateReport(ctx, fileID)
		if err != nil {
			PrintError(errors.New("A report is already being generated or scan is in progress. Please wait."))
			return false, err
		}

		for result.Progress < 100 {
			time.Sleep(100 * time.Millisecond)
			result, err = client.Reports.FetchReportResult(ctx, result.ID)
			if err != nil {
				PrintError(errors.New("Faild to fetch report result"))
				return false, err
			}
			fmt.Printf("\rGeneration progress: %d%%", result.Progress)
		}
		fmt.Println("\nReport generated successfully.")
	}

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
