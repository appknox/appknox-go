package helper

import (
    "context"
    "fmt"
    "strconv"
    "net/http"

    // "github.com/appknox/appknox-go/appknox"
)

// ScheduleDastAutomation calls the DynamicScanService.ScheduleDastAutomation
// to POST /api/v2/files/:file_id/dynamicscans with mode & enable_api_capture.
func ScheduleDastAutomation(fileID int, mode int, enableAPICapture bool) error {
    client := getClient()

    // Directly call the Dynamic Scans service method
    resp, err := client.DynamicScans.ScheduleDastAutomation(
        context.Background(),
        fileID,
        mode,
        enableAPICapture,
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
        // If you'd like to parse any error message from resp.Body, you could do that here.
        return fmt.Errorf("unexpected status code: %s", strconv.Itoa(resp.StatusCode))
    }
}
