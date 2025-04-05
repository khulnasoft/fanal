// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/khulnasoft/fanal/types"
)

// createTestConfig creates a test configuration for benchmarks
func createTestConfig(t *testing.T, outputEnabled map[string]bool) {
	// Store original config
	originalConfig := config

	// Reset after test
	t.Cleanup(func() {
		config = originalConfig
	})

	// Create a minimal configuration for testing
	config = &types.Configuration{
		Debug:        false,
		Customfields: map[string]string{"env": "test"},
		Customtags:   []string{"benchmark"},
	}

	// Enable specific outputs based on the provided map
	if outputEnabled["slack"] {
		config.Slack.WebhookURL = "https://hooks.slack.com/services/test"
		config.Slack.MinimumPriority = "debug"
	}

	if outputEnabled["discord"] {
		config.Discord.WebhookURL = "https://discord.com/api/webhooks/test"
		config.Discord.MinimumPriority = "debug"
	}

	if outputEnabled["elasticsearch"] {
		config.Elasticsearch.HostPort = "http://localhost:9200"
		config.Elasticsearch.MinimumPriority = "debug"
	}
}

// createTestPayload creates a test payload with specified size and complexity
func createTestPayload(size string, complexity string) io.Reader {
	payload := types.KhulnasoftPayload{
		Output:       "Test output for benchmark",
		Priority:     types.Debug,
		Rule:         "Test rule",
		Time:         time.Now().UTC().Format(time.RFC3339),
		OutputFields: make(map[string]interface{}),
		Tags:         []string{"test", "benchmark"},
	}

	// Adjust payload based on size
	switch size {
	case "small":
		// Default is already small
	case "medium":
		payload.Output += " with additional text repeated to increase size"
		for i := 0; i < 10; i++ {
			payload.Tags = append(payload.Tags, "tag"+string(rune(i)))
		}
	case "large":
		payload.Output += " with much more text repeated multiple times to significantly increase the payload size"
		for i := 0; i < 50; i++ {
			payload.Tags = append(payload.Tags, "tag"+string(rune(i)))
		}
	}

	// Adjust complexity
	switch complexity {
	case "simple":
		// Default is already simple
	case "moderate":
		payload.OutputFields["process"] = map[string]interface{}{
			"name":    "test-process",
			"pid":     12345,
			"command": "test-command",
		}
		payload.OutputFields["user"] = map[string]interface{}{
			"name": "test-user",
			"uid":  1000,
		}
	case "complex":
		payload.OutputFields["process"] = map[string]interface{}{
			"name":    "test-process",
			"pid":     12345,
			"command": "test-command",
			"args":    []string{"--test", "--benchmark", "--complexity=high"},
			"env": map[string]string{
				"PATH":        "/usr/local/bin:/usr/bin",
				"HOME":        "/home/user",
				"ENVIRONMENT": "production",
			},
		}
		payload.OutputFields["user"] = map[string]interface{}{
			"name":     "test-user",
			"uid":      1000,
			"gid":      1000,
			"home_dir": "/home/user",
			"groups":   []string{"users", "docker", "sudo"},
		}
		payload.OutputFields["container"] = map[string]interface{}{
			"id":       "abcdef1234567890",
			"name":     "test-container",
			"image":    "test-image:latest",
			"runtime":  "docker",
			"labels":   map[string]string{"app": "test", "env": "benchmark"},
			"networks": []string{"bridge", "host"},
		}
		payload.OutputFields["k8s"] = map[string]interface{}{
			"pod": map[string]string{
				"name":      "test-pod",
				"namespace": "test-namespace",
				"uid":       "12345678-abcd-1234-abcd-1234567890ab",
			},
			"container": map[string]string{
				"name":  "test-container",
				"id":    "abcdef1234567890",
				"image": "test-image:latest",
			},
			"node": map[string]string{
				"name": "test-node",
			},
		}
	}

	jsonBytes, _ := json.Marshal(payload)
	return bytes.NewReader(jsonBytes)
}

// BenchmarkMainHandler benchmarks the mainHandler function with various payload sizes
func BenchmarkMainHandler(b *testing.B) {
	tests := []struct {
		name       string
		payloadSize string
		complexity string
	}{
		{"SmallSimple", "small", "simple"},
		{"MediumModerate", "medium", "moderate"},
		{"LargeComplex", "large", "complex"},
	}

	for _, tc := range tests {
		b.Run(tc.name, func(b *testing.B) {
			createTestConfig(b, map[string]bool{})

			// Create a request with the test payload
			jsonReader := createTestPayload(tc.payloadSize, tc.complexity)
			jsonBytes, _ := io.ReadAll(jsonReader)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Create a new request for each iteration
				req, _ := http.NewRequest("POST", "/", bytes.NewReader(jsonBytes))
				w := httptest.NewRecorder()
				
				// Execute the handler
				mainHandler(w, req)
			}
		})
	}
}

// BenchmarkNewKhulnasoftPayload benchmarks the newKhulnasoftPayload function with different complexities
func BenchmarkNewKhulnasoftPayload(b *testing.B) {
	tests := []struct {
		name       string
		complexity string
	}{
		{"SimplePayload", "simple"},
		{"ModeratePayload", "moderate"},
		{"ComplexPayload", "complex"},
	}

	for _, tc := range tests {
		b.Run(tc.name, func(b *testing.B) {
			createTestConfig(b, map[string]bool{})

			// Create a test payload
			jsonReader := createTestPayload("medium", tc.complexity)
			jsonBytes, _ := io.ReadAll(jsonReader)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				reader := bytes.NewReader(jsonBytes)
				_, _ = newKhulnasoftPayload(reader)
			}
		})
	}
}

// BenchmarkForwardEvent benchmarks the forwardEvent function with different output configurations
func BenchmarkForwardEvent(b *testing.B) {
	tests := []struct {
		name           string
		enabledOutputs map[string]bool
	}{
		{"NoOutputs", map[string]bool{}},
		{"SingleOutput", map[string]bool{"slack": true}},
		{"MultipleOutputs", map[string]bool{"slack": true, "discord": true, "elasticsearch": true}},
	}

	for _, tc := range tests {
		b.Run(tc.name, func(b *testing.B) {
			createTestConfig(b, tc.enabledOutputs)

			// Create a test payload
			jsonReader := createTestPayload("medium", "moderate")
			payload := types.KhulnasoftPayload{}
			jsonData, _ := io.ReadAll(jsonReader)
			_ = json.Unmarshal(jsonData, &payload)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Note: We're calling forwardEvent directly, but in a real scenario
				// the outputs would send actual HTTP requests, which we don't want in benchmarks.
				// Ideally, we would mock all clients, but for the benchmark purpose, 
				// this is acceptable as we're measuring the routing logic overhead.
				forwardEvent(payload)
			}
		})
	}
}

