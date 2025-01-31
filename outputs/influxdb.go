// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/types"
)

type influxdbPayload string

func newInfluxdbPayload(khulnasoftpayload types.KhulnasoftPayload) influxdbPayload {
	s := "events,rule=" + strings.Replace(khulnasoftpayload.Rule, " ", "_", -1) + ",priority=" + khulnasoftpayload.Priority.String() + ",source=" + khulnasoftpayload.Source

	for i, j := range khulnasoftpayload.OutputFields {
		switch v := j.(type) {
		case string:
			s += "," + i + "=" + strings.Replace(v, " ", "_", -1)
		default:
			continue
		}
	}

	if khulnasoftpayload.Hostname != "" {
		s += "," + Hostname + "=" + khulnasoftpayload.Hostname
	}

	if len(khulnasoftpayload.Tags) != 0 {
		s += ",tags=" + strings.Join(khulnasoftpayload.Tags, "_")
	}

	s += " value=\"" + khulnasoftpayload.Output + "\""

	return influxdbPayload(s)
}

// InfluxdbPost posts event to InfluxDB
func (c *Client) InfluxdbPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.Influxdb.Add(Total, 1)

	err := c.Post(newInfluxdbPayload(khulnasoftpayload), func(req *http.Request) {
		req.Header.Set("Accept", "application/json")

		if c.Config.Influxdb.Token != "" {
			req.Header.Set("Authorization", "Token "+c.Config.Influxdb.Token)
		}
	})
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:influxdb", "status:error"})
		c.Stats.Influxdb.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "influxdb", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "influxdb"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:influxdb", "status:ok"})
	c.Stats.Influxdb.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "influxdb", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "influxdb"),
		attribute.String("status", OK)).Inc()
}
