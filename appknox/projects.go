package appknox

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// ProjectsService handles communication with the project related
// methods of the Appknox API.
type ProjectsService service

// DRFResponseProject represents for drf response of the Appknox project api.
type DRFResponseProject struct {
	Count    int        `json:"count,omitempty"`
	Next     string     `json:"next,omitempty"`
	Previous string     `json:"previous,omitempty"`
	Results  []*Project `json:"results,omitempty"`
}

// ProjectResponse is a wrapper on DRFResponseProject which will help
// to execute further operations on DRFResponseProject.
type ProjectResponse struct {
	r *DRFResponseProject
	s *ProjectsService
	c *context.Context
}

// GetNext returns the next page items for a project.
func (r *ProjectResponse) GetNext() ([]*Project, *ProjectResponse, error) {
	URL := r.r.Next
	if URL == "" {
		err := errors.New("there are no next items")
		return nil, nil, err
	}
	req, err := r.s.client.NewRequest("GET", URL, nil)
	if err != nil {
		return nil, nil, err
	}

	var drfResponse DRFResponseProject
	_, err = r.s.client.Do(*r.c, req, &drfResponse)
	if err != nil {
		return nil, nil, err
	}
	resp := ProjectResponse{
		r: &drfResponse,
		s: r.s,
		c: r.c,
	}
	return drfResponse.Results, &resp, nil
}

// GetPrevious returns the previous page items for a project.
func (r *ProjectResponse) GetPrevious() ([]*Project, *ProjectResponse, error) {
	URL := r.r.Previous
	if URL == "" {
		err := errors.New("there are no previous items")
		return nil, nil, err
	}
	req, err := r.s.client.NewRequest("GET", URL, nil)
	if err != nil {
		return nil, nil, err
	}

	var drfResponse DRFResponseProject
	_, err = r.s.client.Do(*r.c, req, &drfResponse)
	if err != nil {
		return nil, nil, err
	}
	resp := ProjectResponse{
		r: &drfResponse,
		s: r.s,
		c: r.c,
	}
	return drfResponse.Results, &resp, nil
}

// Project represents a Appknox project.
type Project struct {
	ID          int        `json:"id,omitempty"`
	CreatedOn   *time.Time `json:"created_on,omitempty"`
	UpdatedOn   *time.Time `json:"updated_on,omitempty"`
	PackageName string     `json:"package_name,omitempty"`
	Platform    int        `json:"platform,omitempty"`
	FileCount   int        `json:"file_count,omitempty"`
}

// ProjectListOptions specifies the optional parameters to the
// ProjectsService.List method.
type ProjectListOptions struct {
	Platform string `url:"platform,omitempty"`

	PackageName string `url:"package_name,omitempty"`

	Search string `url:"q,omitempty"`

	ListOptions
}

// List lists the files for a project.
func (s *ProjectsService) List(ctx context.Context, opt *ProjectListOptions) ([]*Project, *ProjectResponse, error) {
	me, _, err := s.client.Me.CurrentAuthenticatedUser(ctx)
	if err != nil {
		return nil, nil, err
	}
	orgID := strconv.Itoa(me.DefaultOrganization)
	u := fmt.Sprintf("api/organizations/%s/projects", orgID)
	URL, err := addOptions(u, opt)
	if err != nil {
		return nil, nil, err
	}
	req, err := s.client.NewRequest("GET", URL, nil)
	if err != nil {
		return nil, nil, err
	}
	var drfResponse DRFResponseProject
	_, err = s.client.Do(ctx, req, &drfResponse)
	resp := ProjectResponse{
		r: &drfResponse,
		s: s,
		c: &ctx,
	}
	return drfResponse.Results, &resp, nil
}
