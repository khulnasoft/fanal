// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/PagerDuty/go-pagerduty"
	"go.opentelemetry.io/otel/attribute"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/types"
)

const (
	USEndpoint string = "https://events.pagerduty.com"
	EUEndpoint string = "https://events.eu.pagerduty.com"
)

// PagerdutyPost posts alert event to Pagerduty
func (c *Client) PagerdutyPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.Pagerduty.Add(Total, 1)

	event := createPagerdutyEvent(khulnasoftpayload, c.Config.Pagerduty)

	if strings.ToLower(c.Config.Pagerduty.Region) == "eu" {
		pagerduty.WithV2EventsAPIEndpoint(EUEndpoint)
	} else {
		pagerduty.WithV2EventsAPIEndpoint(USEndpoint)
	}

	if _, err := pagerduty.ManageEventWithContext(context.Background(), event); err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:pagerduty", "status:error"})
		c.Stats.Pagerduty.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "pagerduty", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "pagerduty"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:pagerduty", "status:ok"})
	c.Stats.Pagerduty.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "pagerduty", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "pagerduty"),
		attribute.String("status", OK)).Inc()
	utils.Log(utils.InfoLvl, c.OutputType, "Create Incident OK")
}

func createPagerdutyEvent(khulnasoftpayload types.KhulnasoftPayload, config types.PagerdutyConfig) pagerduty.V2Event {
	details := make(map[string]interface{}, len(khulnasoftpayload.OutputFields)+4)
	details["rule"] = khulnasoftpayload.Rule
	details["priority"] = khulnasoftpayload.Priority.String()
	details["source"] = khulnasoftpayload.Source
	if len(khulnasoftpayload.Hostname) != 0 {
		khulnasoftpayload.OutputFields[Hostname] = khulnasoftpayload.Hostname
	}
	if len(khulnasoftpayload.Tags) != 0 {
		sort.Strings(khulnasoftpayload.Tags)
		details["tags"] = strings.Join(khulnasoftpayload.Tags, ", ")
	}
	event := pagerduty.V2Event{
		RoutingKey: config.RoutingKey,
		Action:     "trigger",
		Payload: &pagerduty.V2Payload{
			Source:    "khulnasoft",
			Summary:   khulnasoftpayload.Output,
			Severity:  "critical",
			Timestamp: khulnasoftpayload.Time.Format(time.RFC3339),
			Details:   khulnasoftpayload.OutputFields,
		},
	}
	return event
}
