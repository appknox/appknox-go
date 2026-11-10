package helper

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/appknox/appknox-go/appknox"
	"github.com/stretchr/testify/require"
)

func TestRequireKnoxIQCompleted_SkipWithoutFileID(t *testing.T) {
	err := requireKnoxIQCompleted(context.Background(), nil, 0)
	require.NoError(t, err)
}

func TestRequireKnoxIQCompleted_MissingClient(t *testing.T) {
	err := requireKnoxIQCompleted(context.Background(), nil, 375)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing Appknox client")
}

func TestRequireKnoxIQCompleted_Completed(t *testing.T) {
	client := testAppknoxClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/api/knoxiq/file/375/knoxiq_scan/status", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 375, "sast_status": appknox.KnoxIQScanStatusCompleted, "dast_status": 0,
		})
	})
	require.NoError(t, requireKnoxIQCompleted(context.Background(), client, 375))
}

func TestRequireKnoxIQCompleted_DASTOnly(t *testing.T) {
	client := testAppknoxClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":          375,
			"sast_status": appknox.KnoxIQScanStatusDisabled,
			"dast_status": appknox.KnoxIQScanStatusCompleted,
		})
	})
	require.NoError(t, requireKnoxIQCompleted(context.Background(), client, 375))
}

func TestRequireKnoxIQCompleted_NotCompleted(t *testing.T) {
	client := testAppknoxClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":          375,
			"sast_status": appknox.KnoxIQScanStatusPending,
			"dast_status": appknox.KnoxIQScanStatusDisabled,
		})
	})
	err := requireKnoxIQCompleted(context.Background(), client, 375)
	require.Error(t, err)
	require.Contains(t, err.Error(), "knoxiq is not completed for file 375")
	require.Contains(t, err.Error(), "Pending")
	require.Contains(t, err.Error(), "Disabled")
}

func TestRequireKnoxIQCompleted_APIError(t *testing.T) {
	client := testAppknoxClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "You do not have permission to perform this action."})
	})
	err := requireKnoxIQCompleted(context.Background(), client, 375)
	require.Error(t, err)
	require.Contains(t, err.Error(), "knoxiq status check failed")
}
