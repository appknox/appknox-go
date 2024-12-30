package appknox

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/appknox/appknox-go/version"
	"github.com/google/go-querystring/query"
)

const (
	// DefaultAPIHost the default host value
	DefaultAPIHost = "https://api.appknox.com/"
)

// A Client manages communication with the Appknox API.
type Client struct {
	client *http.Client // HTTP client used to communicate with the API.

	// Base URL for API requests. Defaults to the http://api.appknox.com/.
	// BaseURL should always be specified with a trailing slash.
	BaseURL *url.URL

	// AccessToken used interact with Appknox API.
	AccessToken string

	// Reuse a single struct instead of allocating one for each service on the heap.
	common service

	// Service used for uploading an app to Appknox.
	Upload *UploadService

	// Service used for getting the current authenticated user.
	Me *MeService

	// Submissions service is used to interact with appknox submission api.
	Submissions *SubmissionsService

	// Projects service is used to interact with appknox project api.
	Projects *ProjectsService

	// Files service is used to interact with appknox file api.
	Files *FilesService

	ProjectProfiles *ProjectProfilesService
	// Analyses service is used to interact with appknox analyses api.
	Analyses *AnalysesService

	// Vulnerabilities service is used to interact with appknox vulnerability api.
	Vulnerabilities *VulnerabilitiesService

	// OWASP service is used to interact with appknox owasp api.
	OWASP *OWASPService

	// Organizaions service is used to interact with appknox organizations api.
	Organizations *OrganizationsService

	// Reports service is used to interact with appknox reports api.
	Reports *ReportsService

	// Dynamic Scan service is used to interact with appknox DAST related APIs
	DynamicScans *DynamicScanService
}

// NewClient returns a new appknox API client.
func NewClient(accessToken string) (*Client, error) {
	baseEndpoint, err := url.Parse(DefaultAPIHost)
	if err != nil {
		return nil, err
	}

	if !strings.HasSuffix(baseEndpoint.Path, "/") {
		baseEndpoint.Path += "/"
	}

	if accessToken == "" {
		return nil, errors.New("access token can't be empty")
	}

	httpClient := &http.Client{}
	c := &Client{
		client:      httpClient,
		BaseURL:     baseEndpoint,
		AccessToken: accessToken,
	}
	c.common.client = c
	c.Me = (*MeService)(&c.common)
	c.Upload = (*UploadService)(&c.common)
	c.Submissions = (*SubmissionsService)(&c.common)
	c.Projects = (*ProjectsService)(&c.common)
	c.Files = (*FilesService)(&c.common)
	c.Analyses = (*AnalysesService)(&c.common)
	c.ProjectProfiles = (*ProjectProfilesService)(&c.common)
	c.Vulnerabilities = (*VulnerabilitiesService)(&c.common)
	c.OWASP = (*OWASPService)(&c.common)
	c.Organizations = (*OrganizationsService)(&c.common)
	c.Reports = (*ReportsService)(&c.common)
	c.DynamicScans = (*DynamicScanService)(&c.common)
	return c, nil
}

// SetHTTPTransportParams sets http params like Proxy and TLSClientConfig
func (c *Client) SetHTTPTransportParams(proxyURL *url.URL, insecure bool) *Client {
	tr := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	c.client.Transport = tr
	return c
}

type service struct {
	client *Client
}

// Response is a appknox API response. This wraps the standard http.Response
// returned from appknox and provides convenient access to things like
// pagination links.
type Response struct {
	*http.Response
}

func newResponse(r *http.Response) *Response {
	response := &Response{Response: r}
	return response
}

// NewRequest creates an API request. A relative URL can be provided in urlStr,
// in which case it is resolved relative to the BaseURL of the Client.
// Relative URLs should always be specified without a preceding slash. If
// specified, the value pointed to by body is JSON encoded and included as the
// request body.
func (c *Client) NewRequest(method, urlStr string, body interface{}) (*http.Request, error) {
	if !strings.HasSuffix(c.BaseURL.Path, "/") {
		return nil, fmt.Errorf("BaseURL must have a trailing slash, but %q does not", c.BaseURL)
	}
	u, err := c.BaseURL.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		err := enc.Encode(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", c.GetUserAgent())
	authorization := fmt.Sprintf("Token %s", c.AccessToken)
	req.Header.Set("Authorization", authorization)
	return req, nil
}

func (c *Client) GetUserAgent() string {
	return "appknox-go/" + version.Version
}

// NewUploadRequest creates an upload request to upload a file to appknox dashboard.
func (c *Client) NewUploadRequest(method, urlStr string, reader io.Reader, size int64) (*http.Request, error) {
	u, err := c.BaseURL.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, u.String(), reader)
	if err != nil {
		return nil, err
	}
	req.ContentLength = size

	req.Header.Set("Content-Type", "application/octet-stream")
	return req, nil
}

// Do sends an API request and returns the API response. The API response is
// JSON decoded and stored in the value pointed to by v, or returned as an
// error if an API error has occurred. If v implements the io.Writer
// interface, the raw response body will be written to v, without attempting to
// first decode it. If rate limit is exceeded and reset time is in the future,
// Do returns *RateLimitError immediately without making a network API call.
//
// The provided ctx must be non-nil. If it is canceled or times out,
// ctx.Err() will be returned.
func (c *Client) Do(ctx context.Context, req *http.Request, v interface{}) (*Response, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		// If we got an error, and the context has been canceled,
		// the context's error is probably more useful.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// If the error type is *url.Error, sanitize its URL before returning.
		if e, ok := err.(*url.Error); ok {
			if url, err := url.Parse(e.URL); err == nil {
				e.URL = sanitizeURL(url).String()
				return nil, e
			}
		}
		return nil, err
	}
	defer resp.Body.Close()

	response := newResponse(resp)

	err = CheckResponse(resp)
	if err != nil {
		_, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			return response, readErr
		}
		return response, err
	}
	if v != nil {
		if w, ok := v.(io.Writer); ok {
			io.Copy(w, resp.Body)
		} else {
			decErr := json.NewDecoder(resp.Body).Decode(v)
			if decErr == io.EOF {
				decErr = nil // ignore EOF errors caused by empty response body
			}
			if decErr != nil {
				err = decErr
			}
		}
	}
	return response, err
}

func sanitizeURL(uri *url.URL) *url.URL {
	if uri == nil {
		return nil
	}
	return uri
}

// ErrorResponse struct is used for validating the error returned by appknox api.
type ErrorResponse struct {
	Response *http.Response
	Detail   string `json:"detail"`
}

func (r *ErrorResponse) Error() string {
	return fmt.Sprintf("%v %v: %d %v",
		r.Response.Request.Method, sanitizeURL(r.Response.Request.URL),
		r.Response.StatusCode, r.Detail)
}

// Error is custom error object.
type Error struct {
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("Error: %s", e.Message)
}

// CheckResponse checks the API response for errors, and returns them if
// present. A response is considered an error if it has a status code outside
// the 200 range or equal to 202 Accepted.
// API error responses are expected to have either no response
// body, or a JSON response body that maps to ErrorResponse. Any other
// response body will be silently ignored.
func CheckResponse(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 {
		return nil
	}
	errorResponse := &ErrorResponse{Response: r}
	data, err := ioutil.ReadAll(r.Body)
	if err == nil && data != nil {
		json.Unmarshal(data, errorResponse)
	}
	return errorResponse
}

// ListOptions specifies the optional parameters to various List methods that
// support pagination.
type ListOptions struct {
	// For paginated result sets, page of results to retrieve.
	Offset int `url:"offset,omitempty"`

	// For paginated result sets, the number of results to include per page.
	Limit int `url:"limit,omitempty"`
}

func addOptions(s string, opt interface{}) (string, error) {
	v := reflect.ValueOf(opt)
	if v.Kind() == reflect.Ptr && v.IsNil() {
		return s, nil
	}

	u, err := url.Parse(s)
	if err != nil {
		return s, err
	}

	qs, err := query.Values(opt)
	if err != nil {
		return s, err
	}

	u.RawQuery = qs.Encode()
	return u.String(), nil
}
