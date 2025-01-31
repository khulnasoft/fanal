// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"sort"

	"go.opentelemetry.io/otel/attribute"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/types"
)

const (
	// DatadogPath is the path of Datadog's event API
	DatadogPath string = "/api/v1/events"
)

type datadogPayload struct {
	Title      string   `json:"title,omitempty"`
	Text       string   `json:"text,omitempty"`
	AlertType  string   `json:"alert_type,omitempty"`
	SourceType string   `json:"source_type_name,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

func newDatadogPayload(khulnasoftpayload types.KhulnasoftPayload) datadogPayload {
	var d datadogPayload
	tags := make([]string, 0)

	for _, i := range getSortedStringKeys(khulnasoftpayload.OutputFields) {
		tags = append(tags, fmt.Sprintf("%v:%v", i, khulnasoftpayload.OutputFields[i]))

	}
	tags = append(tags, "source:"+khulnasoftpayload.Source, "source:khulnasoft")
	if khulnasoftpayload.Hostname != "" {
		tags = append(tags, Hostname+":"+khulnasoftpayload.Hostname)
	}

	if len(khulnasoftpayload.Tags) != 0 {
		sort.Strings(khulnasoftpayload.Tags)
		tags = append(tags, khulnasoftpayload.Tags...)
	}
	d.Tags = tags

	d.Title = khulnasoftpayload.Rule
	d.Text = khulnasoftpayload.Output
	d.SourceType = "khulnasoft"

	var status string
	switch khulnasoftpayload.Priority {
	case types.Emergency, types.Alert, types.Critical, types.Error:
		status = Error
	case types.Warning:
		status = Warning
	default:
		status = Info
	}
	d.AlertType = status

	return d
}

// DatadogPost posts event to Datadog
func (c *Client) DatadogPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.Datadog.Add(Total, 1)

	err := c.Post(newDatadogPayload(khulnasoftpayload))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:datadog", "status:error"})
		c.Stats.Datadog.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "datadog", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "datadog"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:datadog", "status:ok"})
	c.Stats.Datadog.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "datadog", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "datadog"),
		attribute.String("status", OK)).Inc()
}
