// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/khulnasoft/fanal/types"
)

func TestNewDiscordPayload(t *testing.T) {
	expectedOutput := discordPayload{
		Content:   "",
		AvatarURL: DefaultIconURL,
		Embeds: []discordEmbedPayload{
			{
				Title:       "",
				Description: "This is a test from fanal",
				Color:       "12370112", // light grey
				Fields: []discordEmbedFieldPayload{
					{
						Name:   "rule",
						Value:  "Test rule",
						Inline: true,
					},
					{
						Name:   "priority",
						Value:  "Debug",
						Inline: true,
					},
					{
						Name:   "source",
						Value:  "syscalls",
						Inline: true,
					},
					{
						Name:   "hostname",
						Value:  "test-host",
						Inline: true,
					},
					{
						Name:   "proc.name",
						Value:  fmt.Sprintf("```%s```", "fanal"),
						Inline: true,
					},
					{
						Name:   "tags",
						Value:  "example, test",
						Inline: true,
					},
					{
						Name:   "time",
						Value:  "2001-01-01 01:10:00 +0000 UTC",
						Inline: true,
					},
				},
			},
		},
	}

	var f types.KhulnasoftPayload
	require.Nil(t, json.Unmarshal([]byte(khulnasoftTestInput), &f))
	config := &types.Configuration{
		Discord: types.DiscordOutputConfig{},
	}

	output := newDiscordPayload(f, config)
	require.Equal(t, output, expectedOutput)
}
