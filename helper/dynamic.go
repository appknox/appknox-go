package helper

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/appknox/appknox-go/appknox/enums"
)

// ScheduleDastAutomation calls the DynamicScanService.ScheduleDastAutomation
// to POST /api/v2/files/:file_id/dynamicscans with mode=Automated.
func ScheduleDastAutomation(fileID int) error {
	client := getClient()

	mode := int(enums.DynamicScanMode.Automated)

	// Directly call the Dynamic Scans service method
	resp, err := client.DynamicScans.ScheduleDastAutomation(
		context.Background(),
		fileID,
		mode,
	)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// The API returns 201 (Created) on success
	switch resp.StatusCode {
	case http.StatusCreated: // 201
		return nil
	default:
		return fmt.Errorf("unexpected status code: %s", strconv.Itoa(resp.StatusCode))
	}
}
