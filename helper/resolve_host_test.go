package helper

import (
	"strings"
	"testing"
)

func TestResolveHostAndRegion(t *testing.T) {
	hostMappings := GetHostMappings()

	tests := []struct {
		name         string
		host         string
		region       string
		expectedHost string
		expectError  bool
		errorMessage string
	}{
		// Case: Both host and region are empty, should default to global
		{"Empty host and region", "", "", hostMappings["global"], false, ""},

		// Case: Empty host, valid region
		{"Empty host, valid region", "", "global", hostMappings["global"], false, ""},

		// Case: Empty host, invalid region
		{"Empty host, invalid region", "", "invalid-region", "", true, "Invalid region name: invalid-region. Available regions: global, saudi, uae"},

		// Case: Valid host, ignore region
		{"Valid host, ignore region", "http://custom-host.com", "global", "http://custom-host.com", false, ""},

		// Case: Empty host, valid region 'saudi'
		{"Empty host, valid saudi region", "", "saudi", hostMappings["saudi"], false, ""},

		// Case: Empty host, valid region 'uae'
		{"Empty host, valid uae region", "", "uae", hostMappings["uae"], false, ""},

		// Case: Invalid host URL format
		{"Invalid host URL format", "invalid_url", "", "", true, "invalid host URL: invalid_url"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := ResolveHostAndRegion(test.host, test.region, hostMappings)

			if (err != nil) != test.expectError {
				t.Errorf("Expected error: %v, got: %v", test.expectError, err)
			}

			if test.expectError && err != nil {
				if !strings.Contains(err.Error(), test.errorMessage) {
					t.Errorf("Expected error message: %v, got: %v", test.errorMessage, err.Error())
				}
			}

			if result != test.expectedHost && !test.expectError {
				t.Errorf("Expected host: %s, got: %s", test.expectedHost, result)
			}
		})
	}
}
