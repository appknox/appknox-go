package helper

import (
	"context"
	"fmt"
	//"github.com/appknox/appknox-go/appknox"
)

// ScheduleDastAutomation obtains a client, then POSTs to schedule the dynamic scan.
// It returns nil on success (204), or an error if there's a known/unknown problem.
func ScheduleDastAutomation(fileID int) error {
	// 1. Get your client — either an exported or unexported function from clientinitialize.go
	client := getClient() // or GetClient() if exported

	resp, err := client.DynamicScans.ScheduleDastAutomation(context.Background(), fileID)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}

	// 4. Handle the various known status codes
	switch resp.StatusCode {
	case 204:
		// success => scanning inqueued
		return nil
	case 400:
		return fmt.Errorf("dynamic scan automation is not enabled")
	case 403:
		return fmt.Errorf("there is a dynamic scan in progress, cannot schedule automation at the moment")
	default:
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
