package helper

import (
	"strings"
	"testing"
)

func TestResolveCredentials(t *testing.T) {
	tests := []struct {
		name            string
		accessToken     string
		accessKeyID     string
		accessKeySecret string
		expectError     bool
		errorContains   string
		wantServiceAcct bool
	}{
		{
			name:        "PAT only",
			accessToken: "some-pat-token",
			expectError: false,
		},
		{
			name:            "service account only",
			accessKeyID:     "some-key-id",
			accessKeySecret: "some-secret",
			expectError:     false,
			wantServiceAcct: true,
		},
		{
			name:            "both PAT and service account provided",
			accessToken:     "some-pat-token",
			accessKeyID:     "some-key-id",
			accessKeySecret: "some-secret",
			expectError:     true,
			errorContains:   "not both",
		},
		{
			name:          "neither credential provided",
			expectError:   true,
			errorContains: "credentials missing",
		},
		{
			name:          "only access key id provided",
			accessKeyID:   "some-key-id",
			expectError:   true,
			errorContains: "must be provided together",
		},
		{
			name:            "only access key secret provided",
			accessKeySecret: "some-secret",
			expectError:     true,
			errorContains:   "must be provided together",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			creds, err := resolveCredentials(test.accessToken, test.accessKeyID, test.accessKeySecret)

			if (err != nil) != test.expectError {
				t.Fatalf("expected error: %v, got: %v", test.expectError, err)
			}
			if test.expectError {
				if !strings.Contains(err.Error(), test.errorContains) {
					t.Errorf("expected error to contain %q, got: %v", test.errorContains, err)
				}
				return
			}
			if creds.isServiceAccount() != test.wantServiceAcct {
				t.Errorf("isServiceAccount() = %v, want %v", creds.isServiceAccount(), test.wantServiceAcct)
			}
		})
	}
}
