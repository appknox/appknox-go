package appknox

import (
    "context"
    "fmt"
    "net/http"
    "time"

    "github.com/appknox/appknox-go/appknox/enums"
)

// DynamicScanService handles communication with the dynamic scan (DAST) related
// methods of the Appknox API.
type DynamicScanService service

// DRFResponseDynamicScan represents the DRF response for the Appknox dynamic scan API.
type DRFResponseDynamicScan struct {
    Count    int            `json:"count,omitempty"`
    Next     string         `json:"next,omitempty"`
    Previous string         `json:"previous,omitempty"`
    Results  []*DynamicScan `json:"results"`
}

// DynamicScanResponse is a wrapper around DRFResponseDynamicScan
// that can help with further pagination if needed.
type DynamicScanResponse struct {
    r *DRFResponseDynamicScan
    s *DynamicScanService
    c *context.Context
}

// DynamicScanListOptions is similar to AnalysisListOptions,
// letting us specify limit, offset, etc.
type DynamicScanListOptions struct {
    ListOptions // from appknox.go
    // You can add more fields here if the API supports them
}

// DynamicScan represents a single dynamic scan object (DAST) in Appknox.
type DynamicScan struct {
    ID                       int                         `json:"id,omitempty"`
    File                     int                         `json:"file,omitempty"`
    PackageName              int                         `json:"package_name,omitempty"`
    Mode                     enums.DynamicScanModeType   `json:"mode,omitempty"`
    ModeDisplay              string                      `json:"mode_display,omitempty"`
    Status                   enums.DynamicScanStatusType `json:"status,omitempty"`
    StatusDisplay            string                      `json:"status_display,omitempty"`
    MoriartyDynamicScanRequestID string                  `json:"moriarty_dynamicscanrequest_id,omitempty"`
    EnableAPICapture         bool                        `json:"enable_api_capture,omitempty"`
    MoriartyDynamicScanID    string                      `json:"moriarty_dynamicscan_id,omitempty"`
    MoriartyDynamicScanToken string                      `json:"moriarty_dynamicscan_token,omitempty"`
    StartedByUser            int                         `json:"started_by_user,omitempty"`
    StoppedByUser            int                         `json:"stopped_by_user,omitempty"`
    DeviceUsed               map[string]interface{}      `json:"device_used,omitempty"`
    DevicePreference         map[string]interface{}      `json:"device_preference,omitempty"`
    ErrorCode                string                      `json:"error_code,omitempty"`
    ErrorMessage             string                      `json:"error_message,omitempty"`
    CreatedOn                *time.Time                  `json:"created_on,omitempty"`
    UpdatedOn                *time.Time                  `json:"updated_on,omitempty"`
    EndedOn                  *time.Time                  `json:"ended_on,omitempty"`
    AutoShutDownOn           *time.Time                  `json:"auto_shutdown_on,omitempty"`
    IsAnalysisDone           bool                        `json:"is_analysis_done,omitempty"`
}

// ListByFile lists the dynamic scans for a given file ID.
// Now it accepts an optional *DynamicScanListOptions to set query params (e.g., limit=1).
func (s *DynamicScanService) ListByFile(
    ctx context.Context,
    fileID int,
    opt *DynamicScanListOptions,
) ([]*DynamicScan, *DynamicScanResponse, error) {

    // Base endpoint: e.g. "api/v2/files/123/dynamicscans"
    baseEndpoint := fmt.Sprintf("api/v2/files/%v/dynamicscans", fileID)

    // If user wants limit=1 (or any other limit), we apply it here
    finalURL, err := addOptions(baseEndpoint, opt)
    if err != nil {
        return nil, nil, err
    }

    req, err := s.client.NewRequest(http.MethodGet, finalURL, nil)
    if err != nil {
        return nil, nil, err
    }

    var drfResponse DRFResponseDynamicScan
    _, err = s.client.Do(ctx, req, &drfResponse)
    if err != nil {
        return nil, nil, err
    }
    resp := DynamicScanResponse{
        r: &drfResponse,
        s: s,
        c: &ctx,
    }
    return drfResponse.Results, &resp, nil
}

// ScheduleDastAutomation sends a POST request to schedule a DAST automation
// for the specified file ID. (No changes here unless needed.)
func (s *DynamicScanService) ScheduleDastAutomation(ctx context.Context, fileID int, mode int, enableAPICapture bool,) (*Response, error) {

    // The payload for the POST
    payload := struct {
        Mode            int  `json:"mode"`
        EnableAPICapture bool `json:"enable_api_capture"`
    }{
        Mode:            mode,
        EnableAPICapture: enableAPICapture,
    }

    // POST /api/v2/files/<file_id>/dynamicscans
    endpoint := fmt.Sprintf("api/v2/files/%d/dynamicscans", fileID)

    req, err := s.client.NewRequest(http.MethodPost, endpoint, payload)
    if err != nil {
        return nil, err
    }

    resp, err := s.client.Do(ctx, req, nil)
    if err != nil {
        return nil, err
    }
    return resp, nil
}
