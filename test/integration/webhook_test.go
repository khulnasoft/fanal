// Package integration provides integration tests for fanal components.
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/khulnasoft/fanal/outputs"
	"github.com/khulnasoft/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWebhookIntegration tests the webhook output functionality
func TestWebhookIntegration(t *testing.T) {
	SkipIfNoIntegration(t)

	// Create test context with timeout
	ctx, cancel := context.WithTimeout(TestContext(), 5*time.Second)
	defer cancel()

	// Test cases
	testCases := []struct {
		name           string
		alert          types.Alert
		priority       string
		expectedStatus int
		serverBehavior string // "normal", "timeout", "error"
		shouldProcess  bool
	}{
		{
			name:           "Critical Alert",
			priority:       "critical",
			expectedStatus: http.StatusOK,
			serverBehavior: "normal",
			shouldProcess:  true,
		},
		{
			name:           "Warning Alert",
			priority:       "warning",
			expectedStatus: http.StatusOK,
			serverBehavior: "normal",
			shouldProcess:  true,
		},
		{
			name:           "Debug Alert Below Threshold",
			priority:       "debug",
			expectedStatus: http.StatusOK,
			serverBehavior: "normal",
			shouldProcess:  false, // Should be filtered by priority
		},
		{
			name:           "Server Error",
			priority:       "critical",
			expectedStatus: http.StatusInternalServerError,
			serverBehavior: "error",
			shouldProcess:  true, // Will attempt but fail
		},
		{
			name:           "Server Timeout",
			priority:       "critical",
			expectedStatus: http.StatusOK,
			serverBehavior: "timeout",
			shouldProcess:  true, // Will attempt but timeout
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create alert with specified priority
			alert := CreateTestAlert()
			
			// Convert string priority to type.Priority
			switch tc.priority {
			case "debug":
				alert.Labels["severity"] = "debug"
			case "info":
				alert.Labels["severity"] = "info"
			case "warning":
				alert.Labels["severity"] = "warning"
			case "critical":
				alert.Labels["severity"] = "critical"
			}

			// Create webhook server
			var receivedPayloads []map[string]interface{}
			var serverMutex sync.Mutex
			
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle different server behaviors
				switch tc.serverBehavior {
				case "timeout":
					// Simulate timeout by sleeping longer than the client timeout
					time.Sleep(3 * time.Second)
				case "error":
					// Return error status
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				// Parse and store the received payload
				var payload map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Logf("Failed to decode webhook payload: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				serverMutex.Lock()
				receivedPayloads = append(receivedPayloads, payload)
				serverMutex.Unlock()

				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			// Create webhook client
			config := &types.WebhookOutputConfig{
				Address:         server.URL,
				CustomHeaders:   map[string]string{"X-Test": "true"},
				MinimumPriority: "info", // Set threshold to info
				MutualTLS:       false,
				Format:          "json",
				Timeout:         1, // Short timeout to test timeout handling
			}

			client, err := outputs.NewWebhookClient(config)
			require.NoError(t, err, "Failed to create webhook client")

			// Send alert
			err = client.Send(ctx, alert)

			// Verify results based on test case
			if tc.serverBehavior == "normal" && tc.shouldProcess {
				assert.NoError(t, err, "Expected webhook send to succeed")
				
				// Verify payload was received if we expect it to be processed
				serverMutex.Lock()
				assert.GreaterOrEqual(t, len(receivedPayloads), 1, "Expected at least one payload to be received")
				if len(receivedPayloads) > 0 {
					payload := receivedPayloads[0]
					
					// Verify fields were correctly passed
					assert.Equal(t, alert.Status, payload["status"], "Status field mismatch")
					assert.Equal(t, alert.Labels["severity"], payload["severity"], "Severity field mismatch")
					assert.Contains(t, payload, "startsAt", "startsAt field missing")
				}
				serverMutex.Unlock()
			} else if tc.serverBehavior == "timeout" {
				// Should have a timeout error
				assert.Error(t, err, "Expected timeout error")
				assert.Contains(t, err.Error(), "timeout", "Expected timeout error message")
			} else if tc.serverBehavior == "error" {
				// Should have an HTTP error
				assert.Error(t, err, "Expected HTTP error")
				assert.Contains(t, err.Error(), fmt.Sprintf("%d", tc.expectedStatus), "Expected status code in error")
			} else if !tc.shouldProcess {
				// If below threshold, might not see an error but no payload should be received
				serverMutex.Lock()
				assert.Equal(t, 0, len(receivedPayloads), "Expected no payloads for below-threshold priority")
				serverMutex.Unlock()
			}
		})
	}
}

