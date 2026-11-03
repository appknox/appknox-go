package helper

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// completeRun builds a run whose /complete answers with replies[i] on the
// i-th call (the last reply repeats). A zero status means "hang past the
// per-attempt timeout".
func completeRun(t *testing.T, replies []int) (*knoxFixerRun, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(atomic.AddInt32(&calls, 1)) - 1
		if i >= len(replies) {
			i = len(replies) - 1
		}
		if replies[i] == 0 {
			time.Sleep(200 * time.Millisecond)
			return
		}
		w.WriteHeader(replies[i])
		if replies[i] == 200 {
			json.NewEncoder(w).Encode(map[string]string{"status": "completed"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"code": http.StatusText(replies[i]), "detail": "x"})
	}))
	t.Cleanup(srv.Close)

	oldTimeout, oldBackoff := knoxFixerCompleteTimeout, knoxFixerCompleteBackoff
	knoxFixerCompleteTimeout = 50 * time.Millisecond
	knoxFixerCompleteBackoff = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { knoxFixerCompleteTimeout, knoxFixerCompleteBackoff = oldTimeout, oldBackoff })

	client, err := appknox.NewClient("token")
	require.NoError(t, err)
	base, _ := url.Parse(srv.URL + "/")
	client.BaseURL = base
	return &knoxFixerRun{api: client.KnoxFixer, job: &appknox.KnoxFixerJob{JobID: 1, CLISession: "s_1"}}, &calls
}

func TestCompleteRetriesTimeoutThenSucceeds(t *testing.T) {
	run, calls := completeRun(t, []int{0, 503, 200})
	pr := "https://github.com/o/r/pull/1"
	done, err := run.complete(1, &pr, "t", nil, nil, nil)
	require.NoError(t, err)
	assert.True(t, done)
	assert.EqualValues(t, 3, atomic.LoadInt32(calls))
}

func TestCompleteFailureWithPRDoesNotFailRun(t *testing.T) {
	run, calls := completeRun(t, []int{0})
	pr := "https://github.com/o/r/pull/1"
	done, err := run.complete(1, &pr, "t", nil, nil, nil)
	require.NoError(t, err)
	assert.True(t, done)
	assert.EqualValues(t, 3, atomic.LoadInt32(calls))
}

func TestCompleteFailureWithoutPRIsCLIError(t *testing.T) {
	run, _ := completeRun(t, []int{0})
	done, err := run.complete(1, nil, "", nil, nil, nil)
	require.Error(t, err)
	assert.False(t, done)
	var abortErr *knoxFixerAbort
	require.ErrorAs(t, err, &abortErr)
	assert.Equal(t, "cli_error", abortErr.reason)
}

func TestCompleteDoesNotRetry4xx(t *testing.T) {
	run, calls := completeRun(t, []int{409})
	_, err := run.complete(1, nil, "", nil, nil, nil)
	require.Error(t, err)
	assert.EqualValues(t, 1, atomic.LoadInt32(calls))
}
