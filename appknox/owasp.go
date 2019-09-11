package appknox

import (
	"context"
	"fmt"
)

// OWASPService is used to interact with appknox owasp api.
type OWASPService service

// OWASP represents a Appknox owasp object.
type OWASP struct {
	Code        string `json:"code,omitempty"`
	Description string `json:"description,omitempty"`
	ID          string `json:"id,omitempty"`
	Title       string `json:"title,omitempty"`
	Year        int    `json:"year,omitempty"`
}

// GetByID will get a owasp by id.
func (s *OWASPService) GetByID(ctx context.Context, owaspID string) (*OWASP, *Response, error) {
	u := fmt.Sprintf("api/v2/owasps/%s", owaspID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}
	var owaspResponse OWASP
	resp, err := s.client.Do(ctx, req, &owaspResponse)
	return &owaspResponse, resp, nil
}
