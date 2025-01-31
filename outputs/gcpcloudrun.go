// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/types"
)

// CloudRunFunctionPost call Cloud Function
func (c *Client) CloudRunFunctionPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.GCPCloudRun.Add(Total, 1)

	err := c.Post(khulnasoftpayload, func(req *http.Request) {
		if c.Config.GCP.CloudRun.JWT != "" {
			req.Header.Set(AuthorizationHeaderKey, Bearer+" "+c.Config.GCP.CloudRun.JWT)
		}
	})
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:gcpcloudrun", "status:error"})
		c.Stats.GCPCloudRun.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpcloudrun", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcpcloudrun"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType+"CloudRun", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:gcpcloudrun", "status:ok"})
	c.Stats.GCPCloudRun.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "gcpcloudrun", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcpcloudrun"),
		attribute.String("status", OK)).Inc()
}
