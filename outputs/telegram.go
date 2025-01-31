// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"fmt"
	"strings"
	textTemplate "text/template"

	"go.opentelemetry.io/otel/attribute"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/types"
)

func markdownV2EscapeText(text interface{}) string {

	replacer := strings.NewReplacer(
		"_", "\\_", "*", "\\*", "[", "\\[", "]", "\\]", "(",
		"\\(", ")", "\\)", "~", "\\~", "`", "\\`", ">", "\\>",
		"#", "\\#", "+", "\\+", "-", "\\-", "=", "\\=", "|",
		"\\|", "{", "\\{", "}", "\\}", ".", "\\.", "!", "\\!",
	)

	return replacer.Replace(fmt.Sprintf("%v", text))
}

var (
	telegramMarkdownV2Tmpl = `*\[Khulnasoft\] \[{{markdownV2EscapeText .Priority }}\] {{markdownV2EscapeText .Rule }}*

• *Time*: {{markdownV2EscapeText .Time }}
• *Source*: {{markdownV2EscapeText .Source }}
• *Hostname*: {{markdownV2EscapeText .Hostname }}
• *Tags*: {{ range .Tags }}{{markdownV2EscapeText . }} {{ end }}
• *Fields*:
{{ range $key, $value := .OutputFields }}	  • *{{markdownV2EscapeText $key }}*: {{markdownV2EscapeText $value }}
{{ end }}

**Output**: {{markdownV2EscapeText .Output }}
`
)

// Payload
type telegramPayload struct {
	Text                  string `json:"text,omitempty"`
	ParseMode             string `json:"parse_mode,omitempty"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview,omitempty"`
	ChatID                string `json:"chat_id,omitempty"`
	MessageThreadID       string `json:"message_thread_id,omitempty"`
}

func newTelegramPayload(khulnasoftpayload types.KhulnasoftPayload, config *types.Configuration) telegramPayload {
	payload := telegramPayload{

		ParseMode:             "MarkdownV2",
		DisableWebPagePreview: true,
		ChatID:                config.Telegram.ChatID,
	}

	// Check if message_thread_id is present in khulnasoftpayload
	if config.Telegram.MessageThreadID != "" {
		payload.MessageThreadID = config.Telegram.MessageThreadID
	}

	// template engine
	var textBuffer bytes.Buffer
	funcs := textTemplate.FuncMap{
		"markdownV2EscapeText": markdownV2EscapeText,
	}
	ttmpl, _ := textTemplate.New("telegram").Funcs(funcs).Parse(telegramMarkdownV2Tmpl)
	err := ttmpl.Execute(&textBuffer, khulnasoftpayload)
	if err != nil {
		utils.Log(utils.ErrorLvl, "Telegram", err.Error())
		return payload
	}
	payload.Text = textBuffer.String()

	return payload
}

// TelegramPost posts event to Telegram
func (c *Client) TelegramPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.Telegram.Add(Total, 1)

	err := c.Post(newTelegramPayload(khulnasoftpayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:telegram", "status:error"})
		c.Stats.Telegram.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "telegram", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "telegram"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:telegram", "status:ok"})
	c.Stats.Telegram.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "telegram", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "telegram"),
		attribute.String("status", OK)).Inc()
}
