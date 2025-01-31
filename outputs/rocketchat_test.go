// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"

	"github.com/khulnasoft/fanal/types"
)

func TestNewRocketchatPayload(t *testing.T) {
	expectedOutput := slackPayload{
		Text:     "Rule: Test rule Priority: Debug",
		Username: "Fanal",
		IconURL:  DefaultIconURL,
		Attachments: []slackAttachment{
			{
				Fallback: "This is a test from fanal",
				Color:    PaleCyan,
				Text:     "This is a test from fanal",
				Footer:   "",
				Fields: []slackAttachmentField{
					{
						Title: "rule",
						Value: "Test rule",
						Short: true,
					},
					{
						Title: "priority",
						Value: "Debug",
						Short: true,
					},
					{
						Title: "source",
						Value: "syscalls",
						Short: true,
					},
					{
						Title: "tags",
						Value: "example, test",
						Short: true,
					},
					{
						Title: "proc.name",
						Value: "fanal",
						Short: true,
					},
					{
						Title: "time",
						Value: "2001-01-01 01:10:00 +0000 UTC",
						Short: false,
					},
					{
						Title: "hostname",
						Value: "test-host",
						Short: true,
					},
				},
			},
		},
	}

	var f types.KhulnasoftPayload
	require.Nil(t, json.Unmarshal([]byte(khulnasoftTestInput), &f))
	config := &types.Configuration{
		Rocketchat: types.RocketchatOutputConfig{
			Username: "Fanal",
			Icon:     DefaultIconURL,
		},
	}

	var err error
	config.Rocketchat.MessageFormatTemplate, err = template.New("").Parse("Rule: {{ .Rule }} Priority: {{ .Priority }}")
	require.Nil(t, err)

	output := newRocketchatPayload(f, config)
	require.Equal(t, output, expectedOutput)
}
