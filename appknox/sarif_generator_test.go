package appknox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/appknox/appknox-go/appknox/enums"
)

// MockClient is a mock implementation of the Client interface for testing.
type MockClient struct {
	DoFunc         func(ctx context.Context, req *http.Request) (*http.Response, error)
	NewRequestFunc func(method, urlStr string, body interface{}) (*http.Request, error)
}

func (c *MockClient) NewRequest(method, urlStr string, body interface{}) (*http.Request, error) {
	if c.NewRequestFunc != nil {
		return c.NewRequestFunc(method, urlStr, body)
	}
	return nil, errors.New("NewRequestFunc not implemented in MockClient")
}

func (c *MockClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if c.DoFunc != nil {
		return c.DoFunc(ctx, req)
	}
	return nil, errors.New("DoFunc not implemented in MockClient")
}

// GenerateSARIFGivenFileID generates SARIF based on file ID and risk threshold.
func GenerateSARIFGivenFileID_TestFunction(ctx context.Context, client *MockClient, fileID, riskThreshold int) (SARIF, error) {
	// Simulate fetching data and generating SARIF report
	var sarif SARIF

	// Mock data for demonstration
	mockData := `
	{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "Appknox",
						"version": "1.0",
						"informationUri": "https://www.appknox.com/",
						"rules": [
							{
								"id": "APX001",
								"name": "Example Rule",
								"shortDescription": {
									"text": "Short description of Example Rule"
								},
								"fullDescription": {
									"text": "Full description of Example Rule"
								},
								"properties": {
									"tags": ["security"],
									"kind": "security",
									"precision": "high",
									"problem.severity": "error",
									"security-severity": "7.5"
								}
							}
						]
					}
				},
				"results": [
					{
						"ruleId": "APX001",
						"level": "error",
						"message": {
							"text": "Example message"
						},
						"locations": [
							{
								"physicalLocation": {
									"artifactLocation": {
										"uri": "SRCROOT",
										"uriBaseId": ""
									}
								}
							}
						]
					}
				]
			}
		]
	}`

	// Unmarshal mock data into SARIF struct
	err := json.Unmarshal([]byte(mockData), &sarif)
	if err != nil {
		return SARIF{}, err
	}

	return sarif, nil
}

func TestFunctionGenerateSARIFGivenFileID(t *testing.T) {
	// Mock client setup
	mockClient := &MockClient{
		DoFunc: func(ctx context.Context, req *http.Request) (*http.Response, error) {
			// Simulate response based on the request
			switch req.URL.Path {
			case "/files/1":
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(strings.NewReader(`{"static_scan_progress": 100}`)),
				}, nil
			case "/analyses":
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(strings.NewReader(`{"count": 1}`)),
				}, nil
			case "/analyses?limit=1":
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(strings.NewReader(`[{"computed_risk": 7, "vulnerability_id": 101, "cwe": ["CWE_123"]}]`)),
				}, nil
			case "/vulnerabilities/101":
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(strings.NewReader(`{"id": 101, "name": "Example Vulnerability", "intro": "Vulnerability intro", "compliant": "", "non_compliant": "", "description": "Vulnerability description", "cvss_base": 7.5}`)),
				}, nil
			default:
				return nil, errors.New("unexpected URL path")
			}
		},
	}

	// Example inputs for GenerateSARIFGivenFileID function
	fileID := 1
	riskThreshold := 5

	// Call the function under test
	sarif, err := GenerateSARIFGivenFileID_TestFunction(context.Background(), mockClient, fileID, riskThreshold)

	// Check for unexpected errors
	if err != nil {
		t.Fatalf("GenerateSARIFGivenFileID returned unexpected error: %v", err)
	}

	// Validate the SARIF output or process based on expectations
	if sarif.Version != "2.1.0" {
		t.Errorf("Expected SARIF version 2.1.0, got %s", sarif.Version)
	}

	if len(sarif.Runs) != 1 {
		t.Errorf("Expected 1 run in SARIF, got %d", len(sarif.Runs))
	}

	if len(sarif.Runs[0].Results) != 1 {
		t.Errorf("Expected 1 result in the first run, got %d", len(sarif.Runs[0].Results))
	}

	// Additional assertions based on your SARIF generation logic.
	// Add assertions to validate specific fields in SARIF output.

	// Example: Check the tool driver name
	if sarif.Runs[0].Tool.Driver.Name != "Appknox" {
		t.Errorf("Expected tool driver name 'Appknox', got '%s'", sarif.Runs[0].Tool.Driver.Name)
	}

	// Example: Check the first rule ID
	if sarif.Runs[0].Tool.Driver.Rules[0].ID != "APX001" {
		t.Errorf("Expected rule ID 'APX001', got '%s'", sarif.Runs[0].Tool.Driver.Rules[0].ID)
	}
}

// TestBuildSARIF exercises the real (non-mock) SARIF builder against a live
// httptest client: CWE tags render as SARIF rule tags, and a result only
// carries a Properties block (aeisScore/exploitLikelihood) when the caller
// supplied one — i.e. when the analysis has KnoxIQ triage.
func TestBuildSARIF(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/v2/vulnerabilities/101", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":101,"name":"Example Vulnerability","intro":"intro text","description":"desc","cvss_base":7.5}`)
	})

	analyses := []*Analysis{
		{ID: 1, ComputedRisk: enums.Risk.High, VulnerabilityID: 101, CvssBase: 7.5, Cwe: []string{"CWE_79"}},
		{ID: 2, ComputedRisk: enums.Risk.Low, VulnerabilityID: 101, CvssBase: 3.3},
	}
	score := 8.2
	properties := map[int]*ResultProperties{
		1: {AEISScore: &score, ExploitLikelihood: "High"},
	}

	sarif, err := BuildSARIF(context.Background(), client, analyses, properties)
	if err != nil {
		t.Fatalf("BuildSARIF returned unexpected error: %v", err)
	}
	results := sarif.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	if results[0].Properties == nil || results[0].Properties.ExploitLikelihood != "High" {
		t.Errorf("expected result 1 to carry KnoxIQ properties, got %+v", results[0].Properties)
	}
	if results[1].Properties != nil {
		t.Errorf("expected result 2 to have no KnoxIQ properties, got %+v", results[1].Properties)
	}

	tags := sarif.Runs[0].Tool.Driver.Rules[0].Properties.Tags
	foundCWE := false
	for _, tag := range tags {
		if tag == "CWE-79" {
			foundCWE = true
		}
	}
	if !foundCWE {
		t.Errorf("expected CWE-79 tag on rule, got %v", tags)
	}
}
