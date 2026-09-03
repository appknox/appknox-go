package helper

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/appknox/enums"
	"github.com/cheynewallace/tabby"
)

var terminatingStatuses = []enums.DynamicScanStatusType{
	enums.DynamicScanStatus.AnalysisCompleted, // 22
	enums.DynamicScanStatus.TimedOut,          // 23
	enums.DynamicScanStatus.Error,             // 24
	enums.DynamicScanStatus.Cancelled,         // 25
	enums.DynamicScanStatus.Terminated,        // 26
}

var nonStartedStatuses = []enums.DynamicScanStatusType{
	enums.DynamicScanStatus.InQueue,               // 3 - In queue
	enums.DynamicScanStatus.PreProcessing,         // 1 - Pre-processing
	enums.DynamicScanStatus.ProcessingScanRequest, // 2 - Preparing to scan
	enums.DynamicScanStatus.NotStarted,            // 0 - Not yet started
}

// HandleDynamicScan checks the latest scan and acts accordingly.
func HandleDynamicScan(fileID, riskThreshold int) error {
	client := getClient()

	// Get the final dynamic scan state
	dynamicScan, err := getLatestDynamicScan(client, fileID)
	if err != nil {
		PrintError(err)
		os.Exit(1)
		return err
	}
	if dynamicScan == nil {
		fmt.Println("No dynamic scan is running for the file.")
		return nil
	}

	// Determine action based on scan status
	switch {
	case isInStatuses(dynamicScan.Status, nonStartedStatuses):
		fmt.Println("Dynamic scan is in queue.")
		return nil

	case dynamicScan.Status == enums.DynamicScanStatus.AnalysisCompleted ||
		dynamicScan.Status == enums.DynamicScanStatus.TimedOut:
		fmt.Println("Dynamic scan has completed.")
		return showDynamicVulnerabilities(client, fileID, riskThreshold)

	case isInStatuses(dynamicScan.Status, terminatingStatuses):
		fmt.Printf("Dynamic scan has errored out with status=%s (%d)\n", dynamicScan.Status, dynamicScan.Status)
		if dynamicScan.ErrorMessage != "" {
			fmt.Printf("Error message: %s\n", dynamicScan.ErrorMessage)
		}
		return nil

	default:
		fmt.Println("Request timed out.")
		return nil
	}
}

// getLatestDynamicScan handles polling until a final status is reached.
func getLatestDynamicScan(client *appknox.Client, fileID int) (*appknox.DynamicScan, error) {
	pollTimeout := 60 * time.Minute
	startTime := time.Now()

	for {
		opt := &appknox.DynamicScanListOptions{
			ListOptions: appknox.ListOptions{Limit: 1},
		}

		dynamicScans, _, err := client.DynamicScans.ListByFile(context.Background(), fileID, opt)
		if err != nil {
			return nil, err
		}
		if len(dynamicScans) == 0 {
			return nil, nil
		}

		scan := dynamicScans[0]

		// Exit if scan has reached a final status
		if isInStatuses(scan.Status, terminatingStatuses) ||
			isInStatuses(scan.Status, nonStartedStatuses) {
			return scan, nil
		}

		// Continue polling if scan is still in progress
		fmt.Printf("Dynamic scan is still in progress (status=%s)\n", scan.Status)
		if time.Since(startTime) > pollTimeout {
			fmt.Println("DAST check timed out after 60 minutes.")
			return scan, nil
		}

		time.Sleep(60 * time.Second)
	}
}

// isInStatuses checks if a given scan status belongs to a list of statuses.
func isInStatuses(status enums.DynamicScanStatusType, statusList []enums.DynamicScanStatusType) bool {
	for _, s := range statusList {
		if s == status {
			return true
		}
	}
	return false
}

// showDynamicVulnerabilities fetches & filters vulnerabilities from /files/:id/analyses
func showDynamicVulnerabilities(client *appknox.Client, fileID int, riskThreshold int) error {
	analyses, err := getDynamicAnalyses(client, fileID)
	if err != nil {
		PrintError(err)
		os.Exit(1)
		return err
	}

	var filtered []appknox.Analysis
	for _, a := range analyses {
		if int(a.ComputedRisk) >= riskThreshold {
			filtered = append(filtered, *a)
		}
	}

	if len(filtered) == 0 {
		fmt.Printf("\nNo vulnerabilities found with risk threshold >= %s\n",
			enums.RiskType(riskThreshold))
		fmt.Printf("\nCheck file ID %d on Appknox dashboard for more details.\n", fileID)
		return nil
	}

	fmt.Printf("Found %d vulnerabilities with risk >= %s\n",
		len(filtered), enums.RiskType(riskThreshold))

	t := tabby.New()
	t.AddHeader(
		"ANALYSIS-ID",
		"RISK",
		"CVSS-VECTOR",
		"CVSS-BASE",
		"VULNERABILITY-ID",
		"VULNERABILITY-NAME",
	)
	for _, analysis := range filtered {
		vulnerability, _, err := client.Vulnerabilities.GetByID(context.Background(), analysis.VulnerabilityID)
		if err != nil {
			PrintError(err)
			os.Exit(1)
			return err
		}
		t.AddLine(
			analysis.ID,
			analysis.ComputedRisk,
			analysis.CvssVector,
			analysis.CvssBase,
			analysis.VulnerabilityID,
			vulnerability.Name,
		)
	}

	t.Print()
	return nil
}

// getDynamicAnalyses calls GET /api/v2/files/:file_id/analyses?vulnerability_type=2
func getDynamicAnalyses(client *appknox.Client, fileID int) ([]*appknox.Analysis, error) {
	ctx := context.Background()
	options := &appknox.AnalysisListOptions{
		VulnerabilityType: 2,
	}
	_, dynAnalysisResp, err := client.Analyses.ListByFile(ctx, fileID, options)
	if err != nil {
		PrintError(err)
		os.Exit(1)
		return nil, err
	}

	analysisCount := dynAnalysisResp.GetCount()
	options.ListOptions = appknox.ListOptions{Limit: analysisCount}

	dynamicAnalyses, _, err := client.Analyses.ListByFile(ctx, fileID, options)
	if err != nil {
		PrintError(err)
		os.Exit(1)
		return nil, err
	}
	return dynamicAnalyses, nil
}
