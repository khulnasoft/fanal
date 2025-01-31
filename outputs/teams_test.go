// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/khulnasoft/fanal/types"
)

func TestNewTeamsPayload(t *testing.T) {
	expectedOutput := teamsPayload{
		Type:       "MessageCard",
		Summary:    "This is a test from fanal",
		ThemeColor: "ccfff2",
		Sections: []teamsSection{
			{
				ActivityTitle:    "Fanal",
				ActivitySubTitle: "2001-01-01 01:10:00 +0000 UTC",
				ActivityImage:    "",
				Text:             "This is a test from fanal",
				Facts: []teamsFact{
					{
						Name:  "rule",
						Value: "Test rule",
					},
					{
						Name:  "priority",
						Value: "Debug",
					},
					{
						Name:  "source",
						Value: "syscalls",
					},
					{
						Name:  "hostname",
						Value: "test-host",
					},
					{
						Name:  "proc.name",
						Value: "fanal",
					},
					{
						Name:  "tags",
						Value: "example, test",
					},
				},
			},
		},
	}

	var f types.KhulnasoftPayload
	require.Nil(t, json.Unmarshal([]byte(khulnasoftTestInput), &f))

	output := newTeamsPayload(f, &types.Configuration{})
	require.Equal(t, output, expectedOutput)
}
