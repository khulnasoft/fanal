// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"go.opentelemetry.io/otel/attribute"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/types"
)

type WebUIPayload struct {
	Event   types.KhulnasoftPayload `json:"event"`
	Outputs []string                `json:"outputs"`
}

func newWebUIPayload(khulnasoftpayload types.KhulnasoftPayload) WebUIPayload {
	return WebUIPayload{
		Event:   khulnasoftpayload,
		Outputs: EnabledOutputs,
	}
}

// WebUIPost posts event to Slack
func (c *Client) WebUIPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.WebUI.Add(Total, 1)

	err := c.Post(newWebUIPayload(khulnasoftpayload))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:webui", "status:error"})
		c.Stats.WebUI.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "webui", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "webui"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:webui", "status:ok"})
	c.Stats.WebUI.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "webui", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "webui"),
		attribute.String("status", OK)).Inc()
}
