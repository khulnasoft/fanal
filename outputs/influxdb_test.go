// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/khulnasoft/fanal/types"
)

func TestNewInfluxdbPayload(t *testing.T) {
	expectedOutput := `"events,rule=Test_rule,priority=Debug,source=syscalls,proc.name=fanal,hostname=test-host,tags=test_example value=\"This is a test from fanal\""`
	var f types.KhulnasoftPayload
	require.Nil(t, json.Unmarshal([]byte(khulnasoftTestInput), &f))

	influxdbPayload, err := json.Marshal(newInfluxdbPayload(f))
	require.Nil(t, err)

	require.Equal(t, string(influxdbPayload), expectedOutput)
}
