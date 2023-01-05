package helper

import (
	"context"
	"errors"
	"fmt"
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
