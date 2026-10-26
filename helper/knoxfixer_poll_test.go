package helper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pollServer(t *testing.T, handler func(afterSeq int, session string) (int, interface{})) *appknox.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		afterSeq, _ := strconv.Atoi(r.URL.Query().Get("after_seq"))
		assert.NotEmpty(t, r.Header.Get("X-Appknox-CLI-Version"))
		status, body := handler(afterSeq, r.Header.Get("X-Knoxfixer-Session"))
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	client, err := appknox.NewClient("token")
	require.NoError(t, err)
	base, _ := url.Parse(srv.URL + "/")
	client.BaseURL = base
	return client
}

func TestPollerDeliversEveryMessageInOrder(t *testing.T) {
	// The worker moves plan(1) → need_context(2) → done(3) while the main
	// flow is "busy"; /next is non-destructive, so nothing is lost.
	var step int32
	client := pollServer(t, func(afterSeq int, _ string) (int, interface{}) {
		seq := int(atomic.AddInt32(&step, 1))
		if seq > 3 {
			seq = 3
		}
		types := map[int]string{1: "plan", 2: "need_context", 3: "done"}
		if seq <= afterSeq {
			return 200, map[string]interface{}{"type": "wait", "seq": afterSeq}
		}
		return 200, map[string]interface{}{"type": types[seq], "seq": seq}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	run := &knoxFixerRun{ctx: ctx, api: client.KnoxFixer, job: &appknox.KnoxFixerJob{JobID: 1, CLISession: "s_1"}}
	events := make(chan pollEvent, 8)
	go run.poll(events)
	time.Sleep(200 * time.Millisecond) // main flow busy; poller keeps going
	var got []string
	for ev := range events {
		require.NoError(t, ev.err)
		got = append(got, ev.msg.Type)
	}
	assert.Equal(t, []string{"plan", "need_context", "done"}, got)
}

func TestPollerStopsOnSuperseded(t *testing.T) {
	client := pollServer(t, func(int, string) (int, interface{}) {
		return 409, map[string]string{"code": "superseded", "detail": "another knoxfixer run took over job 1"}
	})
	run := &knoxFixerRun{ctx: context.Background(), api: client.KnoxFixer, job: &appknox.KnoxFixerJob{JobID: 1, CLISession: "old"}}
	events := make(chan pollEvent, 2)
	go run.poll(events)
	ev := <-events
	require.Error(t, ev.err)
	assert.Equal(t, 1, run.handlePollError(ev.err))
	var apiErr *appknox.KnoxFixerAPIError
	require.ErrorAs(t, ev.err, &apiErr)
	assert.Equal(t, "superseded", apiErr.Code)
}
