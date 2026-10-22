package helper

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/appknox/appknox-go/agent"
)

// turnServer answers every turn call with "done" and keeps the bodies it got.
func turnServer(t *testing.T) *[]map[string]any {
	t.Helper()
	var bodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/knoxiq/file/1/autofix/2/turn" {
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		require.NoError(t, json.Unmarshal(raw, &body))
		bodies = append(bodies, body)
		_, _ = w.Write([]byte(`{"type":"done"}`))
	}))
	oldHost, oldToken := viper.GetString("host"), viper.GetString("access-token")
	viper.Set("access-token", "FAKE-TOKEN")
	viper.Set("host", server.URL+"/")
	t.Cleanup(func() {
		viper.Set("access-token", oldToken)
		viper.Set("host", oldHost)
		server.Close()
	})
	return &bodies
}

func TestFixViaMycroft_SendsNoPromptText(t *testing.T) {
	bodies := turnServer(t)
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "A.java"), []byte("class A {}\n"), 0o644))
	s := fixSession{
		root: root,
		job:  &mycroftJob{fileID: 1, id: 2},
		build: buildProfile{
			BuildSystem: "Gradle", Android: true, AGPMajor: 8, buildConfigKnown: true,
		},
	}
	tc := targetContext{
		UnitID:     "a1-F-0",
		Why:        "from the locate answer",
		OtherFiles: []agent.Target{{Path: "B.java", Why: "also from the answer"}},
	}
	prior := &patchViolation{Rule: "malformed-xml", Detail: strings.Repeat("x", 1500)}

	_, err := s.fixViaMycroft(context.Background(), "A.java", tc, prior)
	require.NoError(t, err)

	require.Len(t, *bodies, 1)
	start := (*bodies)[0]["start"].(map[string]any)
	// Paths only: Mycroft takes each file's reason from the locate answer.
	require.Equal(t, map[string]any{"path": "A.java"}, start["target"])
	require.Equal(t, []any{map[string]any{"path": "B.java"}}, start["others"])
	// Typed build facts, not the rendered sentences.
	require.Equal(t, map[string]any{
		"build_system": "Gradle", "android": true, "agp_major": float64(8), "build_config": false,
	}, start["profile"])
	violation := start["violation"].(map[string]any)
	require.Equal(t, "malformed-xml", violation["rule"])
	require.Len(t, violation["detail"], maxViolationDetail)
}
