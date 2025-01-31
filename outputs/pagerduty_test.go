// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"

	"github.com/PagerDuty/go-pagerduty"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft/fanal/types"
)

func TestPagerdutyPayload(t *testing.T) {
	var khulnasoftTestInput = `{"output":"This is a test from fanal","priority":"Debug","rule":"Test rule","hostname":"test-host","time":"2001-01-01T01:10:00Z","output_fields": {"hostname": "test-host", "proc.name":"fanal", "proc.tty": 1234}}`
	var excpectedOutput = pagerduty.V2Event{
		RoutingKey: "",
		Action:     "trigger",
		Payload: &pagerduty.V2Payload{
			Summary:   "This is a test from fanal",
			Source:    "khulnasoft",
			Severity:  "critical",
			Timestamp: "2001-01-01T01:10:00Z",
			Component: "",
			Group:     "",
			Class:     "",
			Details: map[string]interface{}{
				"hostname":  "test-host",
				"proc.name": "fanal",
				"proc.tty":  float64(1234),
			},
		},
	}

	var f types.KhulnasoftPayload
	json.Unmarshal([]byte(khulnasoftTestInput), &f)

	event := createPagerdutyEvent(f, types.PagerdutyConfig{})

	require.Equal(t, excpectedOutput, event)
}
