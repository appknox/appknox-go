package helper

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/appknox/appknox-go/appknox"
	"github.com/magiconair/properties/assert"
	"github.com/spf13/viper"
)

func setup() (client *appknox.Client, mux *http.ServeMux, serverURL string, teardown func()) {
	// mux is the HTTP request multiplexer used with the test server.
	mux = http.NewServeMux()

	// We want to ensure that tests catch mistakes where the endpoint URL is
	// specified as absolute rather than relative. It only makes a difference
	// when there's a non-empty base URL path. So, use that. See issue #752.
	apiHandler := http.NewServeMux()
	apiHandler.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintln(os.Stderr, "FAIL: Client.BaseURL path prefix is not preserved in the request URL:\t"+req.URL.String())
		fmt.Fprintln(os.Stderr, "\tDid you accidentally use an absolute endpoint URL rather than relative?")
		http.Error(w, "Client.BaseURL path prefix is not preserved in the request URL.", http.StatusInternalServerError)
	})

	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(apiHandler)

	// client is the appknox client being tested and is
	// configured to use test server.

	client, err := appknox.NewClient("token")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	url, _ := url.Parse(server.URL + "/")
	client.BaseURL = url
	return client, apiHandler, server.URL, server.Close
}

func TestHelper_ProcessDownloadReports_WithValidData_Success(t *testing.T) {
	_, mux, serverURL, teardown := setup()
	defer teardown()

	// Setting up environment variable to use fake server in this api tests
	viper.Set("host", serverURL+"/")
	viper.Set("insecure", true)
	viper.Set("access-token", "token")

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		resp := fmt.Sprintf(`{
			"count": 1,
			"next": null,
			"previous": null,
			"results": [
				{
					"id": %d,
					"language": "en",
					"progress": 100,
					"rating": "20.73"
				}
			]
		}`, 1)
		fmt.Fprint(w, resp)
	})

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/reports/1/pdf", func(w http.ResponseWriter, r *http.Request) {
		resp := fmt.Sprintf(`{"url":"%s/aws_fake_signed_url1.txt?signature=fake_signature_hash"}`, serverURL)
		fmt.Fprint(w, resp)
	})

	// Starting fake server to accept download request
	mux.HandleFunc("/aws_fake_signed_url1.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `Fake_File_Content`)
	})

	tmpDir := t.TempDir()

	ok, err := ProcessDownloadReports(1, true, false, tmpDir)
	assert.Equal(t, true, ok)
	assert.Equal(t, nil, err)

	// remove files after test
	err = os.Remove(filepath.Join(tmpDir, "aws_fake_signed_url1.txt"))
	assert.Equal(t, nil, err)
}

func TestHelper_ProcessDownloadReports_With_Generate_No_IfFetchLastReportResult_Fail_ShouldFail(t *testing.T) {
	_, mux, serverURL, teardown := setup()
	defer teardown()

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// Setting up environment variable to use fake server in this api tests
	viper.Set("host", serverURL+"/")
	viper.Set("insecure", true)
	viper.Set("access-token", "token")

	ok, err := ProcessDownloadReports(1, true, false, t.TempDir())
	assert.Equal(t, false, ok)
	assert.Equal(t, false, err == nil)
}

func TestHelper_ProcessDownloadReports_With_Generate_No_IfGetReportURL_Fail_ShouldFail(t *testing.T) {
	_, mux, serverURL, teardown := setup()
	defer teardown()

	// Setting up environment variable to use fake server in this api tests
	viper.Set("host", serverURL+"/")
	viper.Set("insecure", true)
	viper.Set("access-token", "token")

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		resp := fmt.Sprintf(`{
			"count": 1,
			"next": null,
			"previous": null,
			"results": [
				{
					"id": %d,
					"language": "en",
					"progress": 100,
					"rating": "20.73"
				}
			]
		}`, 1)
		fmt.Fprint(w, resp)
	})

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/reports/1/pdf", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	ok, err := ProcessDownloadReports(1, true, false, t.TempDir())
	assert.Equal(t, false, ok)
	assert.Equal(t, false, err == nil)
}

func TestHelper_ProcessDownloadReports_With_Generate_No_IfDownloadFile_Fail_ShouldFail(t *testing.T) {
	_, mux, serverURL, teardown := setup()
	defer teardown()

	// Setting up environment variable to use fake server in this api tests
	viper.Set("host", serverURL+"/")
	viper.Set("insecure", true)
	viper.Set("access-token", "token")

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		resp := fmt.Sprintf(`{
			"count": 1,
			"next": null,
			"previous": null,
			"results": [
				{
					"id": %d,
					"language": "en",
					"progress": 100,
					"rating": "20.73"
				}
			]
		}`, 1)
		fmt.Fprint(w, resp)
	})

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/reports/1/pdf", func(w http.ResponseWriter, r *http.Request) {
		resp := fmt.Sprintf(`{"url":"%s/aws_fake_signed_url1.txt?signature=fake_signature_hash"}`, serverURL)
		fmt.Fprint(w, resp)
	})

	// Starting fake server to accept request
	mux.HandleFunc("/aws_fake_signed_url1.txt", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	tmpDir := t.TempDir()

	ok, err := ProcessDownloadReports(1, true, false, tmpDir)
	assert.Equal(t, false, ok)
	assert.Equal(t, false, err == nil)

	// remove files after test
	err = os.Remove(filepath.Join(tmpDir, "aws_fake_signed_url1.txt"))
	assert.Equal(t, nil, err)
}

func TestHelper_ProcessDownloadReports_With_Generate_Yes_Success(t *testing.T) {
	_, mux, serverURL, teardown := setup()
	defer teardown()

	// Setting up environment variable to use fake server in this api tests
	viper.Set("host", serverURL+"/")
	viper.Set("insecure", true)
	viper.Set("access-token", "token")

	// Starting fake server to accept request for generate reports
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		resp := fmt.Sprintf(`{
					"id": %d,
					"language": "en",
					"progress": 50,
					"rating": "20.73"
				}`, 1)
		fmt.Fprint(w, resp)
	})

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/reports/1", func(w http.ResponseWriter, r *http.Request) {
		resp := fmt.Sprintf(`{
					"id": %d,
					"language": "en",
					"progress": 100,
					"rating": "20.73"
				}`, 1)
		fmt.Fprint(w, resp)
	})

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/reports/1/pdf", func(w http.ResponseWriter, r *http.Request) {
		resp := fmt.Sprintf(`{"url":"%s/aws_fake_signed_url1.txt?signature=fake_signature_hash"}`, serverURL)
		fmt.Fprint(w, resp)
	})

	// Starting fake server to accept download request
	mux.HandleFunc("/aws_fake_signed_url1.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `Fake_File_Content`)
	})

	tmpDir := t.TempDir()

	ok, err := ProcessDownloadReports(1, true, true, tmpDir)
	assert.Equal(t, true, ok)
	assert.Equal(t, nil, err)

	// remove files after test
	// remove files after test
	err = os.Remove(filepath.Join(tmpDir, "aws_fake_signed_url1.txt"))
	assert.Equal(t, nil, err)
}
func TestHelper_ProcessDownloadReports_With_Generate_Yes_IfAPIFails_Should_Fail(t *testing.T) {
	_, mux, serverURL, teardown := setup()
	defer teardown()

	// Starting fake server to accept download request
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// Setting up environment variable to use fake server in this api tests
	viper.Set("host", serverURL+"/")
	viper.Set("insecure", true)
	viper.Set("access-token", "token")

	ok, err := ProcessDownloadReports(1, true, true, t.TempDir())
	assert.Equal(t, false, ok)
	assert.Equal(t, false, err == nil)
}
func TestHelper_ProcessDownloadReports_With_Generate_Yes_and_Generate_Report_Fails_Should_Fail(t *testing.T) {
	_, mux, serverURL, teardown := setup()
	defer teardown()

	// Setting up environment variable to use fake server in this api tests
	viper.Set("host", serverURL+"/")
	viper.Set("insecure", true)
	viper.Set("access-token", "token")

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	ok, err := ProcessDownloadReports(1, true, true, t.TempDir())
	assert.Equal(t, false, ok)
	assert.Equal(t, "A report is already being generated or scan is in progress. Please wait.", err.Error())
}

func TestHelper_ProcessDownloadReports_WithInvalidData_Fail(t *testing.T) {
	ok, err := ProcessDownloadReports(1, false, false, t.TempDir())
	assert.Equal(t, false, ok)
	assert.Equal(t, "Downloading PDF reports is not a fully supported/experimental feature. Please opt-in by specifying --allow-experimental-features in the command.", err.Error())
}

func TestHelper_ProcessDownloadReports_With_Generate_Yes_FetchReportResultFail_ShouldFail(t *testing.T) {
	_, mux, serverURL, teardown := setup()
	defer teardown()

	// Setting up environment variable to use fake server in this api tests
	viper.Set("host", serverURL+"/")
	viper.Set("insecure", true)
	viper.Set("access-token", "token")

	// Starting fake server to accept request for generate reports
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		resp := fmt.Sprintf(`{
					"id": %d,
					"language": "en",
					"progress": 50,
					"rating": "20.73"
				}`, 1)
		fmt.Fprint(w, resp)
	})

	// Starting fake server to accept download request
	mux.HandleFunc("/api/v2/reports/1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	ok, err := ProcessDownloadReports(1, true, true, t.TempDir())
	assert.Equal(t, false, ok)
	assert.Equal(t, false, err == nil)
}
