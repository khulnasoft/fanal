// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"

	"github.com/khulnasoft/fanal/types"
)

func TestNewCliqPayload(t *testing.T) {
	expectedOutput := cliqPayload{
		Text: "\U000026AA Rule: Test rule Priority: Debug",
		Bot: cliqBot{
			Name:  "Fanal",
			Image: DefaultIconURL,
		},
		Slides: []cliqSlide{
			{
				Type: "text",
				Data: "This is a test from fanal",
			},
			{
				Type:  "table",
				Title: "",
				Data: &cliqTableData{
					Headers: []string{
						"field",
						"value",
					},
					Rows: []cliqTableRow{
						{
							Field: "rule",
							Value: "Test rule",
						},
						{
							Field: "priority",
							Value: "Debug",
						},
						{
							Field: "hostname",
							Value: "test-host",
						},
						{
							Field: "proc.name",
							Value: "fanal",
						},
						{
							Field: "time",
							Value: "2001-01-01 01:10:00 +0000 UTC",
						},
					},
				},
			},
		},
	}

	var f types.KhulnasoftPayload
	require.Nil(t, json.Unmarshal([]byte(khulnasoftTestInput), &f))
	config := &types.Configuration{
		Cliq: types.CliqOutputConfig{
			Icon:     DefaultIconURL,
			UseEmoji: true,
		},
	}

	var err error
	config.Cliq.MessageFormatTemplate, err = template.New("").Parse("Rule: {{ .Rule }} Priority: {{ .Priority }}")
	require.Nil(t, err)

	output := newCliqPayload(f, config)
	require.Equal(t, output, expectedOutput)
}
