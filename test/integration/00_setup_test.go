// Package integration provides the foundation for integration tests in the fanal project.
// These tests connect to actual services and verify end-to-end functionality.
package integration

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/khulnasoft/fanal/types"
	"github.com/stretchr/testify/require"
)

// Global test configuration and variables
var (
	// TestTimeout is the maximum duration for integration tests
	TestTimeout = 30 * time.Second
	
	// IntegrationFlag controls whether integration tests run
	// Set INTEGRATION=1 to enable integration tests
	IntegrationFlag = os.Getenv("INTEGRATION") == "1"
	
	setupOnce sync.Once
	teardownOnce sync.Once
	
	// testContext is used across integration tests with timeout
	testContext context.Context
	testCancel  context.CancelFunc
)

// TestMain handles setup and teardown for all integration tests
func TestMain(m *testing.M) {
	// Skip all tests if integration testing is disabled
	if !IntegrationFlag {
		fmt.Println("Integration tests disabled. Use INTEGRATION=1 to enable.")
		os.Exit(0)
	}

	// Setup test environment
	setup()
	
	// Create a base context with timeout for all tests
	testContext, testCancel = context.WithTimeout(context.Background(), TestTimeout)
	
	// Run the tests
	code := m.Run()
	
	// Cleanup after tests
	teardown()
	
	os.Exit(code)
}

// setup initializes the test environment
func setup() {
	setupOnce.Do(func() {
		fmt.Println("Setting up integration test environment...")
		// TODO: Add any global test setup here
		// - Create test data
		// - Start mock services
		// - Initialize test configuration
	})
}

// teardown cleans up the test environment
func teardown() {
	teardownOnce.Do(func() {
		fmt.Println("Tearing down integration test environment...")
		if testCancel != nil {
			testCancel()
		}
		// TODO: Add any global test cleanup here
		// - Remove test data
		// - Stop mock services
	})
}

// SkipIfNoIntegration skips a test if integration testing is disabled
func SkipIfNoIntegration(t *testing.T) {
	if !IntegrationFlag {
		t.Skip("Skipping integration test")
	}
}

// TestContext returns the base context for integration tests
func TestContext() context.Context {
	return testContext
}

// CreateTestAlert creates a sample alert for testing
func CreateTestAlert() types.Alert {
	return types.Alert{
		Status:      "firing",
		Labels:      map[string]string{"severity": "critical", "test": "true"},
		Annotations: map[string]string{"summary": "Test alert", "description": "This is a test alert"},
		StartsAt:    time.Now(),
		EndsAt:      time.Now().Add(1 * time.Hour),
	}
}

// CreateTestConfig creates a minimal test configuration
func CreateTestConfig() map[string]interface{} {
	return map[string]interface{}{
		"name":     "integration-test",
		"interval": "10s",
		"enabled":  true,
	}
}

// AssertOutputProcessed checks if an alert was processed by an output
func AssertOutputProcessed(t *testing.T, err error, outputName string) {
	require.NoError(t, err, "Error processing alert in %s output", outputName)
}

/*
HOW TO WRITE INTEGRATION TESTS

Integration tests should:
1. Be in separate files named with a descriptive test name, e.g., "slack_integration_test.go"
2. Use the utilities provided in this file for common operations
3. Create realistic test scenarios with actual services when possible
4. Clean up after themselves to maintain a clean test environment
5. Be skippable in normal test runs unless INTEGRATION=1 is set

Example test structure:

```go
func TestMyOutputIntegration(t *testing.T) {
	SkipIfNoIntegration(t)
	
	// Setup test-specific resources
	// ...
	
	// Create a test alert
	alert := CreateTestAlert()
	
	// Configure and run the output
	// ...
	
	// Verify the results
	// ...
	
	// Cleanup test-specific resources
	// ...
}
```
*/

