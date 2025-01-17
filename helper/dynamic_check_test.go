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

// TestRunDastCheck_NoScans checks the scenario: dynamic_status=0 => no active dynamic scan => "No dynamic scan is running..."
func TestRunDastCheck_NoScans(t *testing.T) {
    // 1. Setup an httptest.Server that returns dynamic_status=0 and no scans
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch {
        case r.URL.Path == "/api/v2/files/123" && r.Method == http.MethodGet:
            fmt.Fprint(w, `{"id":123,"dynamic_status":0}`)
        case r.URL.Path == "/api/v2/files/123/dynamicscans" && r.Method == http.MethodGet:
            fmt.Fprint(w, `{"count":0,"results":[]}`)
        default:
            http.NotFound(w, r)
        }
    }))
    defer server.Close()

    // 2. Provide a fake token & server URL so getClient() won't exit on missing token
    oldHost := viper.GetString("host")
    oldToken := viper.GetString("access-token")
    viper.Set("access-token", "FAKE-TOKEN")
    viper.Set("host", server.URL+"/")
    defer func() {
        viper.Set("access-token", oldToken)
        viper.Set("host", oldHost)
    }()

    // 3. Capture output of RunDastCheck
    output := captureOutput(func() {
        err := RunDastCheck(123, 3)
        assert.NoError(t, err, "We expect no error for the NoScans scenario")
    })

    // 4. Validate
    assert.Contains(t, output, "No dynamic scan is running for the file.")
}

// TestRunDastCheck_InQueue checks the scenario: dynamic_status=1 => "Status: inqueue"
func TestRunDastCheck_InQueue(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/api/v2/files/999" && r.Method == http.MethodGet {
            fmt.Fprint(w, `{"id":999,"dynamic_status":1}`)
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
        err := RunDastCheck(999, 3)
        assert.NoError(t, err)
    })
    assert.Contains(t, output, "Status: inqueue")
}

// TestRunDastCheck_CompletedNoVulns checks scenario: dynamic_status != 0/1 => last scan=22 => 0 vulnerabilities
// Production code prints "No vulnerabilities found with risk threshold >= High" if your enumerated risk=3 => "High".
func TestRunDastCheck_CompletedNoVulns(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch {
        case r.URL.Path == "/api/v2/files/777" && r.Method == http.MethodGet:
            fmt.Fprint(w, `{"id":777,"dynamic_status":5}`)
        case r.URL.Path == "/api/v2/files/777/dynamicscans" && r.Method == http.MethodGet:
            fmt.Fprint(w, `{"count":1,"results":[{"id":222,"status":22,"error_message":""}]}`)
        case r.URL.Path == "/api/v2/files/777/analyses" && r.Method == http.MethodGet:
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
        err := RunDastCheck(777, 3)
        assert.NoError(t, err)
    })

    // Your production code prints "No vulnerabilities found with risk threshold >= High"
    // because risk=3 => enumerated string "High"
    assert.Contains(t, output, "Dynamic scan has completed successfully.")
    assert.Contains(t, output, "No vulnerabilities found with risk threshold >= High")
}

// TestRunDastCheck_CompletedWithVulns checks scenario: last scan=22 => multiple vulns => enumerated risk string.
func TestRunDastCheck_CompletedWithVulns(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch {
        case r.URL.Path == "/api/v2/files/555" && r.Method == http.MethodGet:
            fmt.Fprint(w, `{"id":555,"dynamic_status":5}`)
        case r.URL.Path == "/api/v2/files/555/dynamicscans" && r.Method == http.MethodGet:
            fmt.Fprint(w, `{"count":1,"results":[{"id":300,"status":22,"error_message":""}]}`)
        case r.URL.Path == "/api/v2/files/555/analyses" && r.Method == http.MethodGet:
            fmt.Fprint(w, `{
				"count":2,
				"results":[
				  {"id":10,"risk":3,"computed_risk":3,"vulnerability":111},
				  {"id":11,"risk":3,"computed_risk":3,"vulnerability":222}
				]
			}`)
        case r.URL.Path == "/api/v2/vulnerabilities/111" && r.Method == http.MethodGet:
            fmt.Fprint(w, `{"id":111,"name":"SQL Injection"}`)
        case r.URL.Path == "/api/v2/vulnerabilities/222" && r.Method == http.MethodGet:
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
        err := RunDastCheck(555, 3)
        assert.NoError(t, err)
    })

    // Expect "risk >= High" to match production code enumerating "3" => "High"
    assert.Contains(t, output, "Dynamic scan has completed successfully.")
    assert.Contains(t, output, "Found 2 vulnerabilities with risk >= High")
    assert.Contains(t, output, "SQL Injection")
    assert.Contains(t, output, "Buffer Overflow")
}

// TestRunDastCheck_FileNotFound checks scenario: 404 => code forcibly calls os.Exit(1), which is "fine" per your requirement
func TestRunDastCheck_FileNotFound(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/api/v2/files/9999" && r.Method == http.MethodGet {
            w.WriteHeader(http.StatusNotFound)
            fmt.Fprint(w, `{"detail":"Not found."}`)
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

    // The code calls os.Exit(1) on 404 => so we won't see more after capturing
    output := captureOutput(func() {
        err := RunDastCheck(9999, 3)
        // We do a basic check for error, but once os.Exit(1) is called, the process ends
        assert.Error(t, err)
    })

    assert.Contains(t, output, "doesn’t exist")
}
