package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError string
	}{
		{
			name:          "valid API key",
			headers:       http.Header{"Authorization": []string{"ApiKey test-api-key-123"}},
			expectedKey:   "test-api-key-123",
			expectedError: "",
		},
		{
			name:          "no authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name:          "empty authorization header",
			headers:       http.Header{"Authorization": []string{""}},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name:          "malformed header - missing ApiKey prefix",
			headers:       http.Header{"Authorization": []string{"Bearer token123"}},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name:          "malformed header - only ApiKey without key",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name:          "malformed header - wrong case",
			headers:       http.Header{"Authorization": []string{"apikey test-key"}},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name:          "valid API key with extra spaces",
			headers:       http.Header{"Authorization": []string{"ApiKey my-secret-key-456"}},
			expectedKey:   "my-secret-key-456",
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %v, want %v", key, tt.expectedKey)
			}

			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("GetAPIKey() error = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Errorf("GetAPIKey() error = nil, want %v", tt.expectedError)
				} else if err.Error() != tt.expectedError {
					t.Errorf("GetAPIKey() error = %v, want %v", err.Error(), tt.expectedError)
				}
			}
		})
	}
}
