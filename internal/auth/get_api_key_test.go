package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
		expectErr   bool
	}{
		{
			name:        "no authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "valid ApiKey header",
			headers:     http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expectedKey: "my-secret-key",
			expectedErr: nil,
		},
		{
			name:        "wrong scheme (Bearer)",
			headers:     http.Header{"Authorization": []string{"Bearer some-token"}},
			expectedKey: "",
			expectErr:   true,
		},
		{
			name:        "malformed header with no value",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			if tc.expectedErr != nil {
				if err != tc.expectedErr {
					t.Errorf("expected error %v, got %v", tc.expectedErr, err)
				}
			} else if tc.expectErr {
				if err == nil {
					t.Error("expected an error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			if key != tc.expectedKey {
				t.Errorf("expected key %q, got %q", tc.expectedKey, key)
			}
		})
	}
}
