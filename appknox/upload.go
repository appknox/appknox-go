package appknox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// UploadService is used to interact with appknox file upload api.
type UploadService service

// Upload struct is used to validate the response of ile upload api.
type Upload struct {
	URL           string `json:"url,omitempty"`
	FileKey       string `json:"file_key,omitempty"`
	FileKeySigned string `json:"file_key_signed,omitempty"`
	SubmissionID  int    `json:"submission_id,omitempty"`
}

// UploadFile is used to upload a file to appknox dashboard.
// Returns the fileID.
func (s *UploadService) UploadFile(ctx context.Context, file *os.File) (*int, error) {
	me, _, err := s.client.Me.CurrentAuthenticatedUser(ctx)
	if err != nil {
		return nil, err
	}
	orgID := strconv.Itoa(me.DefaultOrganization)
	u := fmt.Sprintf("api/organizations/%s/upload_app", orgID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	var uploadResponse Upload
	_, err3 := s.client.Do(ctx, req, &uploadResponse)
	if err3 != nil {
		return nil, err3
	}
	URL := uploadResponse.URL

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	req3, err := s.client.NewUploadRequest("PUT", URL, file, stat.Size())
	if err != nil {
		return nil, err
	}
	_, err1 := s.client.Do(ctx, req3, nil)
	if err1 != nil {
		return nil, err1
	}

	req4, err := s.client.NewRequest("POST", u, uploadResponse)
	if err != nil {
		return nil, err
	}
	_, err2 := s.client.Do(ctx, req4, &uploadResponse)
	if err2 != nil {
		return nil, err2
	}
	submissionID := uploadResponse.SubmissionID
	var file1 int
	start := time.Now()
	for file1 == 0 {
		submission, _, err := s.client.Submissions.GetByID(ctx, submissionID)
		if err != nil {
			return nil, err
		}
		reason := submission.Reason
		if reason != "" {
			return nil, errors.New(reason)
		}
		if time.Since(start) > 10*time.Second {
			return nil, errors.New("Request timed out")
		}
		file1 = submission.File
	}
	return &file1, nil
}
