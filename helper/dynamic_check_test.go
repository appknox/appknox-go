package helper

import (
    "bytes"
    "fmt"
    "io"
    "net/http"
    "net/http/httptest"
    "os"
    "testing"

    "github.com/spf13/viper"
    "github.com/stretchr/testify/assert"
)

// captureOutput captures console output while running a function.
func captureOutput(f func()) string {
    old := os.Stdout
    r, w, _ := os.Pipe()
    os.Stdout = w

    f()

    _ = w.Close()
    os.Stdout = old
    var buf bytes.Buffer
    _, _ = io.Copy(&buf, r)
    return buf.String()
}

// TestHandleDynamicScan_NoScans ensures the function properly handles no scans available.
func TestHandleDynamicScan_NoScans(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch r.URL.Path {
        case "/api/v2/files/123/dynamicscans":
            fmt.Fprint(w, `{"count":0,"results":[]}`)
        default:
            http.NotFound(w, r)
        }
    }))
    defer server.Close()

    oldHost := viper.GetString("host")
    oldToken := viper.GetString("access-token")
    viper.Set("access-token", "FAKE-TOKEN")
    viper.Set("host", server.URL+"/")
    defer func() {
        viper.Set("access-token", oldToken)
        viper.Set("host", oldHost)
    }()

    output := captureOutput(func() {
        err := HandleDynamicScan(123, 3)
        assert.NoError(t, err)
    })

    assert.Contains(t, output, "No dynamic scan is running for the file.")
}

// TestHandleDynamicScan_InQueue verifies that scans in queue are properly identified.
func TestHandleDynamicScan_InQueue(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/api/v2/files/999/dynamicscans" {
            fmt.Fprint(w, `{"count":1,"results":[{"id":999,"status":3}]}`) // InQueue
        } else {
            http.NotFound(w, r)
        }
    }))
    defer server.Close()

    oldHost := viper.GetString("host")
    oldToken := viper.GetString("access-token")
    viper.Set("access-token", "FAKE-TOKEN")
    viper.Set("host", server.URL+"/")
    defer func() {
        viper.Set("access-token", oldToken)
        viper.Set("host", oldHost)
    }()

    output := captureOutput(func() {
        err := HandleDynamicScan(999, 3)
        assert.NoError(t, err)
    })

    assert.Contains(t, output, "Dynamic scan is in queue.")
}

// TestHandleDynamicScan_CompletedNoVulns ensures that completed scans with no vulnerabilities are handled correctly.
func TestHandleDynamicScan_CompletedNoVulns(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch r.URL.Path {
        case "/api/v2/files/777/dynamicscans":
            fmt.Fprint(w, `{"count":1,"results":[{"id":777,"status":22}]}`) // AnalysisCompleted
        case "/api/v2/files/777/analyses":
            fmt.Fprint(w, `{"count":0,"results":[]}`)
        default:
            http.NotFound(w, r)
        }
    }))
    defer server.Close()

    oldHost := viper.GetString("host")
    oldToken := viper.GetString("access-token")
    viper.Set("access-token", "FAKE-TOKEN")
    viper.Set("host", server.URL+"/")
    defer func() {
        viper.Set("access-token", oldToken)
        viper.Set("host", oldHost)
    }()

    output := captureOutput(func() {
        err := HandleDynamicScan(777, 3)
        assert.NoError(t, err)
    })

    assert.Contains(t, output, "Dynamic scan has completed.")
    assert.Contains(t, output, "No vulnerabilities found with risk threshold >= High")
}

// TestHandleDynamicScan_CompletedWithVulns ensures vulnerabilities are printed when found.
func TestHandleDynamicScan_CompletedWithVulns(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch r.URL.Path {
        case "/api/v2/files/555/dynamicscans":
            fmt.Fprint(w, `{"count":1,"results":[{"id":555,"status":22}]}`) // AnalysisCompleted
        case "/api/v2/files/555/analyses":
            fmt.Fprint(w, `{"count":2,"results":[{"id":10,"computed_risk":3,"vulnerability":111},{"id":11,"computed_risk":3,"vulnerability":222}]}`)
        case "/api/v2/vulnerabilities/111":
            fmt.Fprint(w, `{"id":111,"name":"SQL Injection"}`)
        case "/api/v2/vulnerabilities/222":
            fmt.Fprint(w, `{"id":222,"name":"Buffer Overflow"}`)
        default:
            http.NotFound(w, r)
        }
    }))
    defer server.Close()

    oldHost := viper.GetString("host")
    oldToken := viper.GetString("access-token")
    viper.Set("access-token", "FAKE-TOKEN")
    viper.Set("host", server.URL+"/")
    defer func() {
        viper.Set("access-token", oldToken)
        viper.Set("host", oldHost)
    }()

    output := captureOutput(func() {
        err := HandleDynamicScan(555, 3)
        assert.NoError(t, err)
    })

    assert.Contains(t, output, "Dynamic scan has completed.")
    assert.Contains(t, output, "Found 2 vulnerabilities with risk >= High")
    assert.Contains(t, output, "SQL Injection")
    assert.Contains(t, output, "Buffer Overflow")
}

// TestHandleDynamicScan_Error ensures error states are caught.
func TestHandleDynamicScan_Error(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/api/v2/files/888/dynamicscans" {
            fmt.Fprint(w, `{"count":1,"results":[{"id":888,"status":24,"error_message":"Scan failed"}]}`) // Error
        } else {
            http.NotFound(w, r)
        }
    }))
    defer server.Close()

    oldHost := viper.GetString("host")
    oldToken := viper.GetString("access-token")
    viper.Set("access-token", "FAKE-TOKEN")
    viper.Set("host", server.URL+"/")
    defer func() {
        viper.Set("access-token", oldToken)
        viper.Set("host", oldHost)
    }()

    output := captureOutput(func() {
        err := HandleDynamicScan(888, 3)
        assert.NoError(t, err)
    })

    assert.Contains(t, output, "Dynamic scan has errored out with status=Error (24)")
    assert.Contains(t, output, "Error message: Scan failed")
}

// TestHandleDynamicScan_FileNotFound ensures the function handles 404 correctly.
// will be implemented once os.exit(1) is accounted for in real code
