package appknox

import (
	"context"
	"fmt"
)

// OrganizationsService is used to interact with appknox owasp api.
type OrganizationsService service

// DRFResponseOrganization represents for drf response of the Appknox organizations api.
type DRFResponseOrganization struct {
	Count    int64           `json:"count,omitempty"`
	Next     string          `json:"next,omitempty"`
	Previous string          `json:"previous,omitempty"`
	Results  []*Organization `json:"results,omitempty"`
}

// Organization represents a Appknox organization object.
type Organization struct {
	ID            int    `json:"id,omitempty"`
	Name          string `json:"name,omitempty"`
	ProjectsCount int    `json:"projects_count,omitempty"`
}

// OrganizationResponse is a wrapper on DRFResponseOrganization which will help
// to execute further operations on DRFResponseOrganization.
type OrganizationResponse struct {
	r *DRFResponseOrganization
	s *OrganizationsService
	c *context.Context
}

// List lists organizations for the current user.
func (s *OrganizationsService) List(ctx context.Context) ([]*Organization, *OrganizationResponse, error) {
	u := fmt.Sprintf("api/organizations")
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var drfResponse DRFResponseOrganization
	_, err = s.client.Do(ctx, req, &drfResponse)
	if err != nil {
		return nil, nil, err
	}
	resp := OrganizationResponse{
		r: &drfResponse,
		s: s,
		c: &ctx,
	}
	return drfResponse.Results, &resp, nil
}
