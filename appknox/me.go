package appknox

import (
	"context"
	"fmt"
)

// MeService is used to interact appknox me api.
type MeService service

// Me struct is used to validate the response to returned by me api.
type Me struct {
	ID                  int    `json:"id,omitempty"`
	Username            string `json:"username,omitempty"`
	Email               string `json:"email,omitempty"`
	DefaultOrganization int    `json:"default_organization,omitempty"`
}

// CurrentAuthenticatedUser is used to get the details about the current
// authenticated user at appknox.
func (s *MeService) CurrentAuthenticatedUser(ctx context.Context) (*Me, *Response, error) {
	u := fmt.Sprintf("api/me")
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}
	var meResponse Me
	resp, err := s.client.Do(ctx, req, &meResponse)
	if err != nil {
		return nil, nil, err
	}
	return &meResponse, resp, nil
}
