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

func newRocketchatPayload(khulnasoftpayload types.KhulnasoftPayload, config *types.Configuration) slackPayload {
	var (
		messageText string
		attachments []slackAttachment
		attachment  slackAttachment
		fields      []slackAttachmentField
		field       slackAttachmentField
	)

	if config.Rocketchat.OutputFormat == All || config.Rocketchat.OutputFormat == Fields || config.Rocketchat.OutputFormat == "" {
		field.Title = Rule
		field.Value = khulnasoftpayload.Rule
		field.Short = true
		fields = append(fields, field)
		field.Title = Priority
		field.Value = khulnasoftpayload.Priority.String()
		field.Short = true
		fields = append(fields, field)
		field.Title = Source
		field.Value = khulnasoftpayload.Source
		field.Short = true
		fields = append(fields, field)
		if len(khulnasoftpayload.Tags) != 0 {
			sort.Strings(khulnasoftpayload.Tags)
			field.Title = Tags
			field.Value = strings.Join(khulnasoftpayload.Tags, ", ")
			field.Short = true
			fields = append(fields, field)
		}

		for _, i := range getSortedStringKeys(khulnasoftpayload.OutputFields) {
			field.Title = i
			field.Value = khulnasoftpayload.OutputFields[i].(string)
			if len([]rune(khulnasoftpayload.OutputFields[i].(string))) < 36 {
				field.Short = true
			} else {
				field.Short = false
			}
			fields = append(fields, field)
		}

		field.Title = Time
		field.Short = false
		field.Value = khulnasoftpayload.Time.String()
		fields = append(fields, field)
		if khulnasoftpayload.Hostname != "" {
			field.Title = Hostname
			field.Value = khulnasoftpayload.Hostname
			field.Short = true
			fields = append(fields, field)
		}
	}

	attachment.Fallback = khulnasoftpayload.Output
	attachment.Fields = fields
	if config.Rocketchat.OutputFormat == All || config.Rocketchat.OutputFormat == Text || config.Rocketchat.OutputFormat == "" {
		attachment.Text = khulnasoftpayload.Output
	}

	if config.Rocketchat.MessageFormatTemplate != nil {
		buf := &bytes.Buffer{}
		if err := config.Rocketchat.MessageFormatTemplate.Execute(buf, khulnasoftpayload); err != nil {
			utils.Log(utils.ErrorLvl, "RocketChat", fmt.Sprintf("Error expanding RocketChat message: %v", err))
		} else {
			messageText = buf.String()
		}
	}

	if config.Rocketchat.OutputFormat == All || config.Rocketchat.OutputFormat == Fields || config.Rocketchat.OutputFormat == "" {
		var color string
		switch khulnasoftpayload.Priority {
		case types.Emergency:
			color = Red
		case types.Alert:
			color = Orange
		case types.Critical:
			color = Orange
		case types.Error:
			color = Red
		case types.Warning:
			color = Yellow
		case types.Notice:
			color = Lightcyan
		case types.Informational:
			color = LigthBlue
		case types.Debug:
			color = PaleCyan
		}
		attachment.Color = color

		attachments = append(attachments, attachment)
	}

	iconURL := DefaultIconURL
	if config.Rocketchat.Icon != "" {
		iconURL = config.Rocketchat.Icon
	}

	s := slackPayload{
		Text:        messageText,
		Username:    config.Rocketchat.Username,
		IconURL:     iconURL,
		Attachments: attachments}

	return s
}

// RocketchatPost posts event to Rocketchat
func (c *Client) RocketchatPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.Rocketchat.Add(Total, 1)

	err := c.Post(newRocketchatPayload(khulnasoftpayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:rocketchat", "status:error"})
		c.Stats.Rocketchat.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "rocketchat", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "rocketchat"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:rocketchat", "status:ok"})
	c.Stats.Rocketchat.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "rocketchat", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "rocketchat"),
		attribute.String("status", OK)).Inc()
}
