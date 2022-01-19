package appknox

import (
	"context"
	"fmt"
)

// ProjectProfileService is used to interact with project profile api.
type ProjectProfilesService service

type RegulatoryPreference struct {
	Value bool `json:"value,omitempty"`
}

// ProjectProfileReportPreference struct is used to validate the response
// of prpject profile report preference API
type ProjectProfileReportPreference struct {
	ShowPcidss RegulatoryPreference `json:"show_pcidss,omitempty"`
	ShowHipaa  RegulatoryPreference `json:"show_hipaa,omitempty"`
	ShowGdpr   RegulatoryPreference `json:"show_gdpr,omitempty"`
}

// CurrentAuthenticatedUser is used to get the details about the current
// authenticated user at appknox.
func (s *ProjectProfilesService) GetProjectProfileReportPreference(ctx context.Context, fileID int) (*ProjectProfileReportPreference, *Response, error) {
	file, resp, err := s.client.Files.GetByID(ctx, fileID)
	if err != nil {
		return nil, nil, err
	}
	// Get the profile report preference
	u := fmt.Sprintf("api/profiles/%v/report_preference", file.ProfileID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}
	var reportPrefResponse ProjectProfileReportPreference
	resp, err = s.client.Do(ctx, req, &reportPrefResponse)
	if err != nil {
		return nil, nil, err
	}
	return &reportPrefResponse, resp, nil

}
