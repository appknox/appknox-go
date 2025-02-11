package appknox

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/appknox/appknox-go/appknox/enums"
)

// AnalysesService handles communication with the analyses related
// methods of the Appknox API.
type AnalysesService service

// DRFResponseAnalysis represents for drf response of the Appknox analyses api.
type DRFResponseAnalysis struct {
	Count    int         `json:"count,omitempty"`
	Next     string      `json:"next,omitempty"`
	Previous string      `json:"previous,omitempty"`
	Results  []*Analysis `json:"results"`
}

// AnalysisResponse is a wrapper on DRFResponseAnalysis which will help
// to execute further operations on DRFResponseAnalysis.
type AnalysisResponse struct {
	r *DRFResponseAnalysis
	s *AnalysesService
	c *context.Context
}

// GetNext returns the next page items for a analysis.
func (r *AnalysisResponse) GetNext() ([]*Analysis, *AnalysisResponse, error) {
	URL := r.r.Next
	if URL == "" {
		err := errors.New("there are no next items")
		return nil, nil, err
	}
	req, err := r.s.client.NewRequest("GET", URL, nil)
	if err != nil {
		return nil, nil, err
	}

	var drfResponse DRFResponseAnalysis
	_, err = r.s.client.Do(*r.c, req, &drfResponse)
	if err != nil {
		return nil, nil, err
	}
	resp := AnalysisResponse{
		r: &drfResponse,
		s: r.s,
		c: r.c,
	}
	return drfResponse.Results, &resp, nil
}

// GetPrevious returns the previous page items for a analysis.
func (r *AnalysisResponse) GetPrevious() ([]*Analysis, *AnalysisResponse, error) {
	URL := r.r.Previous
	if URL == "" {
		err := errors.New("there are no previous items")
		return nil, nil, err
	}
	req, err := r.s.client.NewRequest("GET", URL, nil)
	if err != nil {
		return nil, nil, err
	}

	var drfResponse DRFResponseAnalysis
	_, err = r.s.client.Do(*r.c, req, &drfResponse)
	if err != nil {
		return nil, nil, err
	}
	resp := AnalysisResponse{
		r: &drfResponse,
		s: r.s,
		c: r.c,
	}
	return drfResponse.Results, &resp, nil
}

// GetCount will return total number of items in the analysis response.
func (r *AnalysisResponse) GetCount() int {
	return r.r.Count
}

// Analysis represents the appknox file analysis.
type Analysis struct {
	ID              int                     `json:"id,omitempty"`
	Risk            enums.RiskType          `json:"risk,omitempty"`
	OverRiddenRisk  enums.RiskType          `json:"overridden_risk,omitempty"`
	ComputedRisk    enums.RiskType          `json:"computed_risk,omitempty"`
	Status          enums.AnalysisStateType `json:"status,omitempty"`
	CvssVector      string                  `json:"cvss_vector,omitempty"`
	CvssBase        float64                 `json:"cvss_base,omitempty"`
	CvssVersion     int                     `json:"cvss_version,omitempty"`
	Owasp           []string                `json:"owasp,omitempty"`
	Pcidss          []string                `json:"pcidss,omitempty"`
	Hipaa           []string                `json:"hipaa,omitempty"`
	Asvs            []string                `json:"asvs,omitempty"`
	Cwe             []string                `json:"cwe,omitempty"`
	Gdpr            []string                `json:"gdpr,omitempty"`
	Mstg            []string                `json:"mstg,omitempty"`
	Owaspapi2023    []string                `json:"owaspapi2023,omitempty"`
	Masvs           []string                `json:"masvs,omitempty"`
	Nistsp80053     []string                `json:"nistsp80053,omitempty"`
	Nistsp800171    []string                `json:"nistsp800171,omitempty"`
	Sama            []string                `json:"sama,omitempty"`
	Owaspmobile2024 []string                `json:"owaspmobile2024,omitempty"`
	Findings        []Finding               `json:"findings,omitempty"`
	UpdatedOn       *time.Time              `json:"updated_on,omitempty"`
	VulnerabilityID int                     `json:"vulnerability,omitempty"`
}

type Finding struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
}

// AnalysisListOptions specifies the optional parameters to the
// AnalysesService.List method.
type AnalysisListOptions struct {
	VulnerabilityType int `url:"vulnerability_type,omitempty"`
	ListOptions
}

// ListByFile lists the analyses for a file.
func (s *AnalysesService) ListByFile(ctx context.Context, fileID int, opt *AnalysisListOptions) ([]*Analysis, *AnalysisResponse, error) {
	u := fmt.Sprintf("api/v2/files/%v/analyses", fileID)
	URL, err := addOptions(u, opt)
	if err != nil {
		return nil, nil, err
	}
	req, err := s.client.NewRequest("GET", URL, nil)
	if err != nil {
		return nil, nil, err
	}

	var drfResponse DRFResponseAnalysis
	_, err = s.client.Do(ctx, req, &drfResponse)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			fileId := strconv.Itoa(fileID)
			return nil, nil, errors.New("Analyses for fileID " + fileId + " doesn’t exist. Are you sure " + fileId + " is a fileID?")
		}
		return nil, nil, err
	}
	resp := AnalysisResponse{
		r: &drfResponse,
		s: s,
		c: &ctx,
	}
	return drfResponse.Results, &resp, nil
}
