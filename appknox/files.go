package appknox

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/appknox/appknox-go/appknox/enums"
)

// FilesService handles communication with the file related
// methods of the Appknox API.
type FilesService service

// DRFResponseFile represents for drf response of the Appknox file api.
type DRFResponseFile struct {
	Count    int64   `json:"count,omitempty"`
	Next     string  `json:"next,omitempty"`
	Previous string  `json:"previous,omitempty"`
	Results  []*File `json:"results,omitempty"`
}

// FileResponse is a wrapper on DRFResponseFile which will help
// to execute further operations on DRFResponseFile.
type FileResponse struct {
	r *DRFResponseFile
	s *FilesService
	c *context.Context
}

// GetNext returns the next page items for a file.
func (r *FileResponse) GetNext() ([]*File, *FileResponse, error) {
	URL := r.r.Next
	if URL == "" {
		err := errors.New("there are no next items")
		return nil, nil, err
	}
	req, err := r.s.client.NewRequest("GET", URL, nil)
	if err != nil {
		return nil, nil, err
	}

	var drfResponse DRFResponseFile
	_, err = r.s.client.Do(*r.c, req, &drfResponse)
	if err != nil {
		return nil, nil, err
	}
	resp := FileResponse{
		r: &drfResponse,
		s: r.s,
		c: r.c,
	}
	return drfResponse.Results, &resp, nil
}

// GetPrevious returns the previous page items for a file.
func (r *FileResponse) GetPrevious() ([]*File, *FileResponse, error) {
	URL := r.r.Previous
	if URL == "" {
		err := errors.New("there are no previous items")
		return nil, nil, err
	}
	req, err := r.s.client.NewRequest("GET", URL, nil)
	if err != nil {
		return nil, nil, err
	}

	var drfResponse DRFResponseFile
	_, err = r.s.client.Do(*r.c, req, &drfResponse)
	if err != nil {
		return nil, nil, err
	}
	resp := FileResponse{
		r: &drfResponse,
		s: r.s,
		c: r.c,
	}
	return drfResponse.Results, &resp, nil
}

// File represents a Appknox file.
type File struct {
	ID                 int                        `json:"id,omitempty"`
	Name               string                     `json:"name,omitempty"`
	Version            string                     `json:"version,omitempty"`
	VersionCode        string                     `json:"version_code,omitempty"`
	DynamicStatus      enums.DynamicScanStateType `json:"dynamic_status,omitempty"`
	APIScanProgress    int                        `json:"api_scan_progress,omitempty"`
	IsStaticDone       bool                       `json:"is_static_done,omitempty"`
	IsDynamicDone      bool                       `json:"is_dynamic_done,omitempty"`
	StaticScanProgress int                        `json:"static_scan_progress,omitempty"`
	APIScanStatus      enums.AnalysisStateType    `json:"api_scan_status,omitempty"`
	Rating             string                     `json:"rating,omitempty"`
	IsManualDone       bool                       `json:"is_manual_done,omitempty"`
	IsAPIDone          bool                       `json:"is_api_done,omitempty"`
	CreatedOn          *time.Time                 `json:"created_on,omitempty"`
}

// FileListOptions specifies the optional parameters to the
// FilesService.List method.
type FileListOptions struct {
	VersionCode string `url:"version_code,omitempty"`

	ListOptions
}

// ListByProject lists the files for a project.
func (s *FilesService) ListByProject(ctx context.Context, projectID int, opt *FileListOptions) ([]*File, *FileResponse, error) {
	u := fmt.Sprintf("api/projects/%v/files", projectID)
	URL, err := addOptions(u, opt)
	req, err := s.client.NewRequest("GET", URL, nil)
	if err != nil {
		return nil, nil, err
	}

	var drfResponse DRFResponseFile
	_, err = s.client.Do(ctx, req, &drfResponse)
	if err != nil {
		return nil, nil, err
	}
	resp := FileResponse{
		r: &drfResponse,
		s: s,
		c: &ctx,
	}
	return drfResponse.Results, &resp, nil
}

// GetByID get the file with it's id.
func (s *FilesService) GetByID(ctx context.Context, fileID int) (*File, *Response, error) {
	u := fmt.Sprintf("api/v2/files/%v", fileID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}
	var fileResponse File
	resp, err := s.client.Do(ctx, req, &fileResponse)
	return &fileResponse, resp, err
}
