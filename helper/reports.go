package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func ProcessDownloadReportCSV(reportID int, outputFilePath string) error {
	ctx := context.Background()
	client := getClient()
	downloadUrl, err := client.Reports.GetDownloadUrlCSV(ctx, reportID)
	if err != nil {
		return err
	}

	reportData, err := client.Reports.DownloadReportData(ctx, downloadUrl)
	if err != nil {
		return err
	}
	if outputFilePath != "" {
		_, err := client.Reports.WriteReportDataToFile(reportData, outputFilePath)
		if err != nil {
			return errors.New(fmt.Sprintf("Failed to download report. Error: %v", err))
		}
		return nil
	}
	fmt.Println(string(reportData.Bytes()))
	return err

}
func ProcessDownloadReportExcel(reportID int, outputFilePath string) error {
	ctx := context.Background()
	client := getClient()
	downloadUrl, err := client.Reports.GetDownloadUrlExcel(ctx, reportID)
	if err != nil {
		return err
	}
	reportData, err := client.Reports.DownloadReportData(ctx, downloadUrl)
	if err != nil {
		return err
	}
	_, err = client.Reports.WriteReportDataToFile(reportData, outputFilePath)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to download report. Error: %v", err))
	}
	return nil

}

func ProcessCreateReport(fileID int) (reportID int, isNew bool, err error) {
	ctx := context.Background()
	client := getClient()
	report, alreadyExists, err := client.Reports.CreateReport(ctx, fileID)
	if err != nil {
		return 0, false, err
	}
	if alreadyExists {
		// Mycroft decided no regeneration is needed (nothing changed since last report).
		// Fetch the existing report ID so the caller can still download it.
		existing, err := client.Reports.GetLatestReport(ctx, fileID)
		if err != nil {
			return 0, false, errors.New(fmt.Sprintf("Report cannot be generated for file %d. Please ensure the SAST scan is complete.", fileID))
		}
		return existing.ID, false, nil
	}
	return report.ID, true, nil
}

// ProcessKnoxIQReport generates and downloads the KnoxIQ PDF report for a file
// — the same report mycroft produces for a KnoxIQ-triaged file, fetched via the
// CLI. It refuses to run when the file has no KnoxIQ results at all, and it
// verifies the report mycroft actually generated is KnoxIQ-flavoured before
// downloading it, rather than silently handing back a standard report under a
// command whose whole purpose is KnoxIQ. Use `reports create`/`download pdf`
// for a standard report.
func ProcessKnoxIQReport(fileID int, outputDir string, knoxiqTimeout time.Duration) error {
	ctx := context.Background()
	client := getClient()

	if _, available := knoxIQAvailable(ctx, client, fileID); !available {
		return fmt.Errorf(
			"no KnoxIQ results for file %d; use 'appknox reports create' and "+
				"'appknox reports download pdf' for a standard report",
			fileID,
		)
	}

	// Standalone command, so the KnoxIQ wait starts now — there is no
	// preceding static-scan wait to carry time over from.
	if !waitForKnoxIQ(ctx, client, fileID, time.Now().Add(knoxiqTimeout)) {
		PrintError("KnoxIQ triage did not complete within the timeout; the report may not include KnoxIQ results.")
	}

	reportID, _, err := ProcessCreateReport(fileID)
	if err != nil {
		return err
	}
	report, err := client.Reports.GetReport(ctx, reportID)
	if err != nil {
		return err
	}
	if !report.IsKnoxIQ {
		return fmt.Errorf(
			"generated report for file %d does not include KnoxIQ results (no completed KnoxIQ scan)",
			fileID,
		)
	}
	return ProcessDownloadReportPDF(reportID, outputDir)
}

// ProcessDownloadReportPDF downloads a PDF VAPT report and its password file by report ID.
func ProcessDownloadReportPDF(reportID int, outputDir string) error {
	ctx := context.Background()
	client := getClient()

	// Fetch report and poll until progress == 100
	report, err := client.Reports.GetReport(ctx, reportID)
	if err != nil {
		return errors.New(fmt.Sprintf("Report with ID %d not found. Error: %v", reportID, err))
	}
	if report.Progress < 100 {
		timeout := 10 * time.Minute
		interval := 5 * time.Second
		deadline := time.Now().Add(timeout)
		for report.Progress < 100 {
			if time.Now().After(deadline) {
				return errors.New("Report generation timed out after 10 minutes")
			}
			fmt.Printf("Generating report... %d%%\n", report.Progress)
			time.Sleep(interval)
			report, err = client.Reports.GetReport(ctx, reportID)
			if err != nil {
				return errors.New(fmt.Sprintf("Failed to poll report status. Error: %v", err))
			}
		}
	}

	// Get PDF download URL and password
	downloadUrl, password, err := client.Reports.GetDownloadUrlPDF(ctx, report.ID)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to get PDF download URL. Error: %v", err))
	}

	// Download the PDF
	reportData, err := client.Reports.DownloadReportData(ctx, downloadUrl)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to download PDF. Error: %v", err))
	}

	// Write PDF and password file — folder and filename keyed by file_id
	reportDir := filepath.Join(outputDir, strconv.Itoa(report.FileID))
	pdfFilePath := filepath.Join(reportDir, fmt.Sprintf("report_%d.pdf", report.FileID))
	passwordFilePath := filepath.Join(reportDir, fmt.Sprintf("report_%d_password.txt", report.FileID))

	if err = os.MkdirAll(reportDir, os.ModePerm); err != nil {
		return errors.New(fmt.Sprintf("Failed to create output directory. Error: %v", err))
	}
	if _, err = client.Reports.WriteReportDataToFile(reportData, pdfFilePath); err != nil {
		return errors.New(fmt.Sprintf("Failed to write PDF file. Error: %v", err))
	}
	if err = os.WriteFile(passwordFilePath, []byte(password), 0644); err != nil {
		return errors.New(fmt.Sprintf("Failed to write password file. Error: %v", err))
	}

	fmt.Printf("PDF report successfully downloaded to %s\n", pdfFilePath)
	fmt.Printf("Password saved to %s\n", passwordFilePath)

	return nil
}
