// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/khulnasoft/fanal/types"
)

func TestNewOpsgeniePayload(t *testing.T) {
	expectedOutput := opsgeniePayload{
		Message:     "This is a test from fanal",
		Entity:      "Fanal",
		Description: "Test rule",
		Details: map[string]string{
			"hostname":  "test-host",
			"priority":  "Debug",
			"tags":      "test, example",
			"proc_name": "fanal",
			"rule":      "Test rule",
			"source":    "syscalls",
		},
		Priority: "P5",
	}

	var f types.KhulnasoftPayload
	require.Nil(t, json.Unmarshal([]byte(khulnasoftTestInput), &f))
	output := newOpsgeniePayload(f)

	require.Equal(t, output, expectedOutput)
}
