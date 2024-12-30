package helper

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/helper"
	"github.com/stretchr/testify/assert"
)

// Keep references to the original GetClient so we can override/restore
var originalGetClient = helper.GetClient

func overrideGetClient(baseURL string) {
	helper.GetClient = func() *appknox.Client {
		c, _ := appknox.NewClient("FAKE-TOKEN")
		c.BaseURL, _ = url.Parse(baseURL)
		return c
	}
}

func restoreGetClient() {
	helper.GetClient = originalGetClient
}

// captureOutput captures console output (fmt.Print, etc.) during a test.
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

// TestRunDastCheck_NoScans: dynamic_status=0, no scans => "No dynamic scan is running for the file."
func TestRunDastCheck_NoScans(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// dynamic_status=0 => no active dynamic scan
		case r.URL.Path == "/api/v2/files/123" && r.Method == http.MethodGet:
			fmt.Fprintf(w, `{"id":123,"dynamic_status":0}`)
		case r.URL.Path == "/api/v2/files/123/dynamicscans" && r.Method == http.MethodGet:
			fmt.Fprintf(w, `{"count":0,"results":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	overrideGetClient(server.URL + "/")
	defer restoreGetClient()

	output := captureOutput(func() {
		err := helper.RunDastCheck(123, 3)
		assert.NoError(t, err, "We expect no error for 'NoScans' scenario")
	})
	assert.Contains(t, output, "No dynamic scan is running for the file.")
}

// TestRunDastCheck_InQueue: dynamic_status=1 => “Status: inqueue”
func TestRunDastCheck_InQueue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/files/999" && r.Method == http.MethodGet {
			fmt.Fprintf(w, `{"id":999,"dynamic_status":1}`)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	overrideGetClient(server.URL + "/")
	defer restoreGetClient()

	output := captureOutput(func() {
		err := helper.RunDastCheck(999, 3)
		assert.NoError(t, err)
	})
	assert.Contains(t, output, "Status: inqueue")
}

// TestRunDastCheck_CompletedNoVulns: dynamic_status != 0 or 1 => we fetch scans => last scan=22 => no vulnerabilities
func TestRunDastCheck_CompletedNoVulns(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v2/files/777" && r.Method == http.MethodGet:
			fmt.Fprintf(w, `{"id":777,"dynamic_status":5}`)
		case r.URL.Path == "/api/v2/files/777/dynamicscans" && r.Method == http.MethodGet:
			fmt.Fprintf(w, `{"count":1,"results":[{"id":222,"status":22,"error_message":""}]}`)
		case r.URL.Path == "/api/v2/files/777/analyses" && r.Method == http.MethodGet:
			// 0 vulnerabilities
			fmt.Fprintf(w, `{"count":0,"results":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	overrideGetClient(server.URL + "/")
	defer restoreGetClient()

	output := captureOutput(func() {
		err := helper.RunDastCheck(777, 3)
		assert.NoError(t, err)
	})

	assert.Contains(t, output, "Dynamic scan has completed successfully.")
	assert.Contains(t, output, "No vulnerabilities found with risk threshold >= 3")
}

// TestRunDastCheck_CompletedWithVulns: dynamic_status != 0/1 => last scan=22 => we do have vulns
func TestRunDastCheck_CompletedWithVulns(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v2/files/555" && r.Method == http.MethodGet:
			fmt.Fprintf(w, `{"id":555,"dynamic_status":5}`)
		case r.URL.Path == "/api/v2/files/555/dynamicscans" && r.Method == http.MethodGet:
			// last scan is status=22 => completed
			fmt.Fprintf(w, `{"count":1,"results":[{"id":300,"status":22,"error_message":""}]}`)
		case r.URL.Path == "/api/v2/files/555/analyses" && r.Method == http.MethodGet:
			// 2 vulnerabilities
			fmt.Fprintf(w, `{
				"count":2,
				"results":[
				  {"id":10,"risk":3,"computed_risk":3,"vulnerability":111},
				  {"id":11,"risk":3,"computed_risk":3,"vulnerability":222}
				]
			}`)
		case r.URL.Path == "/api/v2/vulnerabilities/111" && r.Method == http.MethodGet:
			fmt.Fprintf(w, `{"id":111,"name":"SQL Injection"}`)
		case r.URL.Path == "/api/v2/vulnerabilities/222" && r.Method == http.MethodGet:
			fmt.Fprintf(w, `{"id":222,"name":"Buffer Overflow"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	overrideGetClient(server.URL + "/")
	defer restoreGetClient()

	output := captureOutput(func() {
		err := helper.RunDastCheck(555, 3)
		assert.NoError(t, err)
	})

	assert.Contains(t, output, "Dynamic scan has completed successfully.")
	assert.Contains(t, output, "Found 2 vulnerabilities with risk >= 3")
	assert.Contains(t, output, "SQL Injection")
	assert.Contains(t, output, "Buffer Overflow")
}

// TestRunDastCheck_FileNotFound: Suppose 404 => "Analyses for fileID ... doesn’t exist"
func TestRunDastCheck_FileNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v2/files/9999" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"detail":"Not found."}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	overrideGetClient(server.URL + "/")
	defer restoreGetClient()

	output := captureOutput(func() {
		err := helper.RunDastCheck(9999, 3)
		assert.Error(t, err)
	})

	assert.Contains(t, output, "doesn’t exist")
}
