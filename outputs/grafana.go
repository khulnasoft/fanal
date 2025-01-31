// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel/attribute"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/types"
)

type grafanaPayload struct {
	DashboardID int      `json:"dashboardId,omitempty"`
	PanelID     int      `json:"panelId,omitempty"`
	Time        int64    `json:"time"`
	TimeEnd     int64    `json:"timeEnd"`
	Tags        []string `json:"tags"`
	Text        string   `json:"text"`
}

type grafanaOnCallPayload struct {
	AlertUID string `json:"alert_uid"`
	State    string `json:"state"`
	Title    string `json:"title"`
	Message  string `json:"message"`
}

// The Content-Type to send along with the request
const GrafanaContentType = "application/json"

func newGrafanaPayload(khulnasoftpayload types.KhulnasoftPayload, config *types.Configuration) grafanaPayload {
	tags := []string{
		"khulnasoft",
		khulnasoftpayload.Priority.String(),
		khulnasoftpayload.Rule,
		khulnasoftpayload.Source,
	}
	if khulnasoftpayload.Hostname != "" {
		tags = append(tags, khulnasoftpayload.Hostname)
	}

	if config.Grafana.AllFieldsAsTags {
		for _, i := range khulnasoftpayload.OutputFields {
			tags = append(tags, fmt.Sprintf("%v", i))
		}
		if len(khulnasoftpayload.Tags) != 0 {
			tags = append(tags, khulnasoftpayload.Tags...)
		}
	}

	g := grafanaPayload{
		Text:    khulnasoftpayload.Output,
		Time:    khulnasoftpayload.Time.UnixNano() / 1000000,
		TimeEnd: khulnasoftpayload.Time.UnixNano() / 1000000,
		Tags:    tags,
	}

	if config.Grafana.DashboardID != 0 {
		g.DashboardID = config.Grafana.DashboardID
	}
	if config.Grafana.PanelID != 0 {
		g.PanelID = config.Grafana.PanelID
	}

	return g
}

func newGrafanaOnCallPayload(khulnasoftpayload types.KhulnasoftPayload) grafanaOnCallPayload {
	return grafanaOnCallPayload{
		AlertUID: khulnasoftpayload.UUID,
		Title:    fmt.Sprintf("[%v] %v", khulnasoftpayload.Priority, khulnasoftpayload.Rule),
		State:    "alerting",
		Message:  khulnasoftpayload.Output,
	}
}

// GrafanaPost posts event to grafana
func (c *Client) GrafanaPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.Grafana.Add(Total, 1)
	c.ContentType = GrafanaContentType

	err := c.Post(newGrafanaPayload(khulnasoftpayload, c.Config), func(req *http.Request) {
		req.Header.Set("Authorization", Bearer+" "+c.Config.Grafana.APIKey)
		for i, j := range c.Config.Grafana.CustomHeaders {
			req.Header.Set(i, j)
		}
	})
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:grafana", "status:error"})
		c.Stats.Grafana.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "grafana", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "grafana"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:grafana", "status:ok"})
	c.Stats.Grafana.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "grafana", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "grafana"),
		attribute.String("status", OK)).Inc()
}

// GrafanaOnCallPost posts event to grafana onCall
func (c *Client) GrafanaOnCallPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.GrafanaOnCall.Add(Total, 1)
	c.ContentType = GrafanaContentType

	err := c.Post(newGrafanaOnCallPayload(khulnasoftpayload), func(req *http.Request) {
		for i, j := range c.Config.GrafanaOnCall.CustomHeaders {
			req.Header.Set(i, j)
		}
	})

	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:grafanaoncall", "status:error"})
		c.Stats.Grafana.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "grafanaoncall", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "grafanaoncall"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:grafanaoncall", "status:ok"})
	c.Stats.Grafana.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "grafanaoncall", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "grafanaoncall"),
		attribute.String("status", OK)).Inc()
}
