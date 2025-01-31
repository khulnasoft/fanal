// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/khulnasoft/fanal/types"
)

func TestNewDatadogLogsPayload(t *testing.T) {
	expectedOutput := `{"title":"Test rule","text":"This is a test from fanal","alert_type":"info","source_type_name":"khulnasoft","tags":["proc.name:fanal", "source:syscalls", "source:khulnasoft", "hostname:test-host", "example", "test"]}`
	var f types.KhulnasoftPayload
	json.Unmarshal([]byte(khulnasoftTestInput), &f)
	s, _ := json.Marshal(newDatadogPayload(f))

	var o1, o2 datadogLogsPayload
	require.Nil(t, json.Unmarshal([]byte(expectedOutput), &o1))
	require.Nil(t, json.Unmarshal(s, &o2))

	require.Equal(t, o1, o2)
}
