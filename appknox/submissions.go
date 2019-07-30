package appknox

import (
	"context"
	"fmt"
)

// SubmissionsService is used to interact with appknox submissions api.
type SubmissionsService service

// Submission represents a Appknox submission object.
type Submission struct {
	ID          int    `json:"id,omitempty"`
	Status      string `json:"status,omitempty"`
	File        int    `json:"file,omitempty"`
	PackageName string `json:"package_name,omitempty"`
	CreatedOn   string `json:"created_on,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// GetByID will get a submission by id.
func (s *SubmissionsService) GetByID(ctx context.Context, submissionID int) (*Submission, *Response, error) {
	u := fmt.Sprintf("api/submissions/%v", submissionID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}
	var submissionResponse Submission
	resp, err := s.client.Do(ctx, req, &submissionResponse)
	return &submissionResponse, resp, nil
}
