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

// Field
type slackAttachmentField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// Attachment
type slackAttachment struct {
	Fallback   string                 `json:"fallback"`
	Color      string                 `json:"color"`
	Text       string                 `json:"text,omitempty"`
	Fields     []slackAttachmentField `json:"fields"`
	Footer     string                 `json:"footer,omitempty"`
	FooterIcon string                 `json:"footer_icon,omitempty"`
}

// Payload
type slackPayload struct {
	Text        string            `json:"text,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconURL     string            `json:"icon_url,omitempty"`
	Channel     string            `json:"channel,omitempty"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

func newSlackPayload(khulnasoftpayload types.KhulnasoftPayload, config *types.Configuration) slackPayload {
	var (
		messageText string
		attachments []slackAttachment
		attachment  slackAttachment
		fields      []slackAttachmentField
		field       slackAttachmentField
	)
	if config.Slack.OutputFormat == All || config.Slack.OutputFormat == Fields || config.Slack.OutputFormat == "" {
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
		if khulnasoftpayload.Hostname != "" {
			field.Title = Hostname
			field.Value = khulnasoftpayload.Hostname
			field.Short = true
			fields = append(fields, field)
		}
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

		attachment.Footer = DefaultFooter
		if config.Slack.Footer != "" {
			attachment.Footer = config.Slack.Footer
		}
	}

	attachment.Fallback = khulnasoftpayload.Output
	attachment.Fields = fields
	if config.Slack.OutputFormat == All || config.Slack.OutputFormat == Text || config.Slack.OutputFormat == "" {
		attachment.Text = khulnasoftpayload.Output
	}

	if config.Slack.MessageFormatTemplate != nil {
		buf := &bytes.Buffer{}
		if err := config.Slack.MessageFormatTemplate.Execute(buf, khulnasoftpayload); err != nil {
			utils.Log(utils.ErrorLvl, "Slack", fmt.Sprintf("Error expanding Slack message: %v", err))
		} else {
			messageText = buf.String()
		}
	}

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

	s := slackPayload{
		Text:        messageText,
		Username:    config.Slack.Username,
		IconURL:     config.Slack.Icon,
		Attachments: attachments}

	if config.Slack.Channel != "" {
		s.Channel = config.Slack.Channel
	}

	return s
}

// SlackPost posts event to Slack
func (c *Client) SlackPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.Slack.Add(Total, 1)

	err := c.Post(newSlackPayload(khulnasoftpayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:slack", "status:error"})
		c.Stats.Slack.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "slack", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "slack"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:slack", "status:ok"})
	c.Stats.Slack.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "slack", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "slack"), attribute.String("status", OK)).Inc()
}
