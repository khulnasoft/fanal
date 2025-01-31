// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/types"
)

// N8NPost posts event to an URL
func (c *Client) N8NPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.N8N.Add(Total, 1)

	err := c.Post(khulnasoftpayload, func(req *http.Request) {
		if c.Config.N8N.User != "" && c.Config.N8N.Password != "" {
			req.SetBasicAuth(c.Config.N8N.User, c.Config.N8N.Password)
		}

		if c.Config.N8N.HeaderAuthName != "" && c.Config.N8N.HeaderAuthValue != "" {
			req.Header.Set(c.Config.N8N.HeaderAuthName, c.Config.N8N.HeaderAuthValue)
		}
	})
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:n8n", "status:error"})
		c.Stats.N8N.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "n8n", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "n8n"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:n8n", "status:ok"})
	c.Stats.N8N.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "n8n", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "n8n"), attribute.String("status", OK)).Inc()
}
