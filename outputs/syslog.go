// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"fmt"
	"log/syslog"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"go.opentelemetry.io/otel/attribute"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/outputs/otlpmetrics"
	"github.com/khulnasoft/fanal/types"
)

func NewSyslogClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	ok := isValidProtocolString(strings.ToLower(config.Syslog.Protocol))
	if !ok {
		return nil, fmt.Errorf("failed to configure Syslog client: invalid protocol %s", config.Syslog.Protocol)
	}

	return &Client{
		OutputType:      "Syslog",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		OTLPMetrics:     otlpMetrics,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

func isValidProtocolString(protocol string) bool {
	return protocol == TCP || protocol == UDP
}

func getCEFSeverity(priority types.PriorityType) string {
	switch priority {
	case types.Debug:
		return "0"
	case types.Informational:
		return "3"
	case types.Notice:
		return "4"
	case types.Warning:
		return "6"
	case types.Error:
		return "7"
	case types.Critical:
		return "8"
	case types.Alert:
		return "9"
	case types.Emergency:
		return "10"
	default:
		return "Uknown"
	}
}

func (c *Client) SyslogPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.Syslog.Add(Total, 1)
	endpoint := fmt.Sprintf("%s:%s", c.Config.Syslog.Host, c.Config.Syslog.Port)

	var priority syslog.Priority
	switch khulnasoftpayload.Priority {
	case types.Emergency:
		priority = syslog.LOG_EMERG
	case types.Alert:
		priority = syslog.LOG_ALERT
	case types.Critical:
		priority = syslog.LOG_CRIT
	case types.Error:
		priority = syslog.LOG_ERR
	case types.Warning:
		priority = syslog.LOG_WARNING
	case types.Notice:
		priority = syslog.LOG_NOTICE
	case types.Informational:
		priority = syslog.LOG_INFO
	case types.Debug:
		priority = syslog.LOG_DEBUG
	}

	sysLog, err := syslog.Dial(c.Config.Syslog.Protocol, endpoint, priority, Khulnasoft)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:syslog", "status:error"})
		c.Stats.Syslog.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "syslog", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "syslog"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	var payload []byte

	if c.Config.Syslog.Format == "cef" {
		s := fmt.Sprintf(
			"CEF:0|Khulnasoft|Khulnasoft|1.0|Khulnasoft Event|%v|%v|uuid=%v start=%v msg=%v source=%v",
			khulnasoftpayload.Rule,
			getCEFSeverity(khulnasoftpayload.Priority),
			khulnasoftpayload.UUID,
			khulnasoftpayload.Time.Format(time.RFC3339),
			khulnasoftpayload.Output,
			khulnasoftpayload.Source,
		)
		if khulnasoftpayload.Hostname != "" {
			s += " hostname=" + khulnasoftpayload.Hostname
		}
		s += " outputfields="
		for i, j := range khulnasoftpayload.OutputFields {
			s += fmt.Sprintf("%v:%v ", i, j)
		}
		if len(khulnasoftpayload.Tags) != 0 {
			s += "tags=" + strings.Join(khulnasoftpayload.Tags, ",")
		}
		payload = []byte(strings.TrimSuffix(s, " "))
	} else {
		payload, _ = json.Marshal(khulnasoftpayload)
	}

	_, err = sysLog.Write(payload)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:syslog", "status:error"})
		c.Stats.Syslog.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "syslog", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "syslog"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:syslog", "status:ok"})
	c.Stats.Syslog.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "syslog", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "syslog"), attribute.String("status", OK)).Inc()
}
