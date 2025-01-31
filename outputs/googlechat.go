// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/types"
)

type header struct {
	Title    string `json:"title"`
	SubTitle string `json:"subtitle"`
}

type keyValue struct {
	TopLabel string `json:"topLabel"`
	Content  string `json:"content"`
}

type widget struct {
	KeyValue keyValue `json:"keyValue,omitempty"`
}

type section struct {
	Widgets []widget `json:"widgets"`
}

type card struct {
	Header   header    `json:"header,omitempty"`
	Sections []section `json:"sections,omitempty"`
}

type googlechatPayload struct {
	Text  string `json:"text,omitempty"`
	Cards []card `json:"cards,omitempty"`
}

func newGooglechatPayload(khulnasoftpayload types.KhulnasoftPayload, config *types.Configuration) googlechatPayload {
	var messageText string
	widgets := []widget{}

	if config.Googlechat.MessageFormatTemplate != nil {
		buf := &bytes.Buffer{}
		if err := config.Googlechat.MessageFormatTemplate.Execute(buf, khulnasoftpayload); err != nil {
			utils.Log(utils.ErrorLvl, "GoogleChat", fmt.Sprintf("Error expanding Google Chat message: %v", err))
		} else {
			messageText = buf.String()
		}
	}

	if config.Googlechat.OutputFormat == Text {
		return googlechatPayload{
			Text: messageText,
		}
	}

	widgets = append(widgets, widget{KeyValue: keyValue{"rule", khulnasoftpayload.Rule}})
	widgets = append(widgets, widget{KeyValue: keyValue{"priority", khulnasoftpayload.Priority.String()}})
	widgets = append(widgets, widget{KeyValue: keyValue{"source", khulnasoftpayload.Source}})
	if khulnasoftpayload.Hostname != "" {
		widgets = append(widgets, widget{KeyValue: keyValue{Hostname, khulnasoftpayload.Hostname}})
	}

	for _, i := range getSortedStringKeys(khulnasoftpayload.OutputFields) {
		widgets = append(widgets, widget{
			KeyValue: keyValue{
				TopLabel: i,
				Content:  khulnasoftpayload.OutputFields[i].(string),
			},
		})
	}

	if len(khulnasoftpayload.Tags) != 0 {
		sort.Strings(khulnasoftpayload.Tags)
		widgets = append(widgets, widget{
			KeyValue: keyValue{
				TopLabel: "tags",
				Content:  strings.Join(khulnasoftpayload.Tags, ", "),
			},
		})
	}

	widgets = append(widgets, widget{KeyValue: keyValue{"time", khulnasoftpayload.Time.String()}})

	return googlechatPayload{
		Text: messageText,
		Cards: []card{
			{
				Sections: []section{
					{Widgets: widgets},
				},
			},
		},
	}
}

// GooglechatPost posts event to Google Chat
func (c *Client) GooglechatPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.GoogleChat.Add(Total, 1)

	err := c.Post(newGooglechatPayload(khulnasoftpayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:googlechat", "status:error"})
		c.Stats.GoogleChat.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "googlechat", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "googlechat"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:googlechat", "status:ok"})
	c.Stats.GoogleChat.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "googlechat", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "googlechat"),
		attribute.String("status", OK)).Inc()
}
