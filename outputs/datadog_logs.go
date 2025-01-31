// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"net/http"
	"sort"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/types"
)

const (
	// DatadogLogsPath is the path of Datadog's logs API
	DatadogLogsPath string = "/api/v2/logs"
)

type datadogLogsPayload struct {
	DDSource string `json:"ddsource,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Service  string `json:"service,omitempty"`
	Message  string `json:"message,omitempty"`
	DDTags   string `json:"ddtags,omitempty"`
}

func newDatadogLogsPayload(khulnasoftpayload types.KhulnasoftPayload, config *types.Configuration) datadogLogsPayload {
	var d datadogLogsPayload

	if len(khulnasoftpayload.Tags) != 0 {
		sort.Strings(khulnasoftpayload.Tags)
		d.DDTags = strings.Join(khulnasoftpayload.Tags, ",")
	}

	d.Hostname = khulnasoftpayload.Hostname
	d.DDSource = strings.ToLower(Khulnasoft)

	d.Message = khulnasoftpayload.String()

	d.Service = config.DatadogLogs.Service

	return d
}

// DatadogLogsPost posts logs to Datadog
func (c *Client) DatadogLogsPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.DatadogLogs.Add(Total, 1)

	reqOpts := []RequestOptionFunc{
		func(req *http.Request) {
			if c.Config.DatadogLogs.APIKey != "" {
				req.Header.Set("DD-API-KEY", c.Config.DatadogLogs.APIKey)
			}
		},
	}

	err := c.Post(newDatadogLogsPayload(khulnasoftpayload, c.Config), reqOpts...)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:datadoglogs", "status:error"})
		c.Stats.DatadogLogs.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "datadoglogs", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "datadoglogs"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:datadoglogs", "status:ok"})
	c.Stats.DatadogLogs.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "datadoglogs", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "datadoglogs"),
		attribute.String("status", OK)).Inc()
}
