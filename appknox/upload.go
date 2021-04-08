package appknox

import (
	"context"
	"errors"
	"fmt"
	"io"
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

// uploadFileUsingReaderHelper is used to get a minio upload url
// and then upload the file to the minio api.
// Returns the Upload object.
func (s *UploadService) uploadFileUsingReaderHelper(ctx context.Context, file io.Reader, size int64, url string) (*Upload, error) {
	req, err := s.client.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	var uploadResponse Upload
	_, err = s.client.Do(ctx, req, &uploadResponse)
	if err != nil {
		return nil, err
	}
	URL := uploadResponse.URL

	req, err = s.client.NewUploadRequest("PUT", URL, file, size)
	if err != nil {
		return nil, err
	}
	_, err = s.client.Do(ctx, req, nil)
	if err != nil {
		return nil, err
	}
	return &uploadResponse, nil
}

// UploadFileUsingReader is used to upload a file to appknox dashboard.
// Returns the submissionID.
func (s *UploadService) UploadFileUsingReader(ctx context.Context, file io.Reader, size int64) (*int, error) {
	me, _, err := s.client.Me.CurrentAuthenticatedUser(ctx)
	if err != nil {
		return nil, err
	}
	orgID := strconv.Itoa(me.DefaultOrganization)
	u := fmt.Sprintf("api/organizations/%s/upload_app", orgID)
	uploadResponse, err := s.uploadFileUsingReaderHelper(ctx, file, size, u)
	if err != nil {
		return nil, err
	}
	req, err := s.client.NewRequest("POST", u, uploadResponse)
	if err != nil {
		return nil, err
	}
	_, err = s.client.Do(ctx, req, &uploadResponse)
	if err != nil {
		return nil, err
	}
	submissionID := uploadResponse.SubmissionID
	return &submissionID, nil
}

// UploadFile is used to upload a file to appknox dashboard.
// Returns the file object.
func (s *UploadService) UploadFile(ctx context.Context, file *os.File) (*File, *Response, error) {
	stat, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	fileSize := stat.Size()
	submissionID, err := s.UploadFileUsingReader(ctx, file, fileSize)
	if err != nil {
		return nil, nil, err
	}
	return s.CheckSubmission(ctx, *submissionID)
}

// CheckSubmission will check submission validation and return a valid file object.
func (s *UploadService) CheckSubmission(ctx context.Context, submissionID int) (*File, *Response, error) {
	start := time.Now()
	var fileID int
	for fileID == 0 {
		submission, _, err := s.client.Submissions.GetByID(ctx, submissionID)
		if err != nil {
			return nil, nil, err
		}
		reason := submission.Reason
		if reason != "" {
			return nil, nil, errors.New(reason)
		}
		if time.Since(start) > 60*time.Second {
			return nil, nil, errors.New("Request timed out")
		}
		fileID = submission.File
	}
	file, resp, err := s.client.Files.GetByID(ctx, fileID)
	if err != nil {
		return nil, nil, err
	}
	return file, resp, nil
}
