// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/types"
)

type opsgeniePayload struct {
	Message     string            `json:"message"`
	Entity      string            `json:"entity,omitempty"`
	Description string            `json:"description,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
	Priority    string            `json:"priority,omitempty"`
}

func newOpsgeniePayload(khulnasoftpayload types.KhulnasoftPayload) opsgeniePayload {
	details := make(map[string]string, len(khulnasoftpayload.OutputFields))
	for i, j := range khulnasoftpayload.OutputFields {
		switch v := j.(type) {
		case string:
			details[strings.ReplaceAll(i, ".", "_")] = v
		default:
			continue
		}
	}

	details["source"] = khulnasoftpayload.Source
	details["rule"] = khulnasoftpayload.Rule
	details["priority"] = khulnasoftpayload.Priority.String()
	if khulnasoftpayload.Hostname != "" {
		details[Hostname] = khulnasoftpayload.Hostname
	}
	if len(khulnasoftpayload.Tags) != 0 {
		details["tags"] = strings.Join(khulnasoftpayload.Tags, ", ")
	}

	var prio string
	switch khulnasoftpayload.Priority {
	case types.Emergency, types.Alert:
		prio = "P1"
	case types.Critical:
		prio = "P2"
	case types.Error:
		prio = "P3"
	case types.Warning:
		prio = "P4"
	default:
		prio = "P5"
	}

	return opsgeniePayload{
		Message:     khulnasoftpayload.Output,
		Entity:      "Fanal",
		Description: khulnasoftpayload.Rule,
		Details:     details,
		Priority:    prio,
	}
}

// OpsgeniePost posts event to OpsGenie
func (c *Client) OpsgeniePost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.Opsgenie.Add(Total, 1)

	err := c.Post(newOpsgeniePayload(khulnasoftpayload), func(req *http.Request) {
		req.Header.Set(AuthorizationHeaderKey, "GenieKey "+c.Config.Opsgenie.APIKey)
	})
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:opsgenie", "status:error"})
		c.Stats.Opsgenie.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "opsgenie", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "opsgenie"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:opsgenie", "status:ok"})
	c.Stats.Opsgenie.Add("ok", 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "opsgenie", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "opsgenie"),
		attribute.String("status", OK)).Inc()
}
