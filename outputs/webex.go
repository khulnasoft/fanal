// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"text/template"

	"go.opentelemetry.io/otel/attribute"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/types"
)

var md string = `# Khulnasoft Rule '{{ .Rule }}'

### {{ .Output }}

Additional informations:
  * Hostname: {{ .Hostname }}
  * Source:   {{ .Source }}  
  * Priority: {{ .Priority }}
  * Tags:
    {{ range $t := .Tags }}
    * {{ $t }}
    {{ end }}
  * Fields:
	{{ range $key, $value := .OutputFields }}
	* {{ $key }}: {{ $value }}
	{{ end }}
`

// Load the md template
var webexTmpl, _ = template.New("markdown").Parse(md)

// the format is {"markdown":"..."}
type webexPayload struct {
	Markdown string `json:"markdown"`
}

func newWebexPayload(khulnasoftpayload types.KhulnasoftPayload) webexPayload {
	var tpl bytes.Buffer

	if err := webexTmpl.Execute(&tpl, khulnasoftpayload); err != nil {
		utils.Log(utils.ErrorLvl, "Webex", err.Error())

	}
	t := webexPayload{
		Markdown: tpl.String(),
	}

	return t
}

// WebexPost sends event to a Webex Room through a Webhook
func (c *Client) WebexPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.Webex.Add(Total, 1)

	err := c.Post(newWebexPayload(khulnasoftpayload))

	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:webex", "status:error"})
		c.Stats.Webhook.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "webex", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "webex"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:webex", "status:ok"})
	c.Stats.Webhook.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "webex", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "webex"), attribute.String("status", OK)).Inc()
}
