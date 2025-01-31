// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"go.opentelemetry.io/otel/attribute"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/types"
)

// TalonPost posts event to an URL
func (c *Client) TalonPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.Talon.Add(Total, 1)

	err := c.Post(khulnasoftpayload)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:talon", "status:error"})
		c.Stats.Talon.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "talon", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "talon"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:talon", "status:ok"})
	c.Stats.Talon.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "talon", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "talon"), attribute.String("status", OK)).Inc()
}
