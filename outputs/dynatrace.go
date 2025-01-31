// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"net/http"
	"regexp"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/types"
)

type dtPayload struct {
	Payload []dtLogMessage `json:"payload"`
}

type dtLogMessage struct {
	Timestamp             string       `json:"timestamp"`
	EventId               string       `json:"event.id,omitempty"`
	EventName             string       `json:"event.name,omitempty"`
	EventProvider         string       `json:"event.provider,omitempty"`
	Severity              string       `json:"severity,omitempty"`
	HostName              string       `json:"host.name,omitempty"`
	LogSource             string       `json:"log.source,omitempty"`
	Content               dtLogContent `json:"content"`
	MitreTechnique        string       `json:"mitre.technique,omitempty"`
	MitreTactic           string       `json:"mitre.tactic,omitempty"`
	ContainerId           string       `json:"container.id,omitempty"`
	ContainerName         string       `json:"container.name,omitempty"`
	ContainerImageName    string       `json:"container.image.name,omitempty"`
	K8sNamespaceName      string       `json:"k8s.namespace.name,omitempty"`
	K8sPodName            string       `json:"k8s.pod.name,omitempty"`
	K8sPodUid             string       `json:"k8s.pod.uid,omitempty"`
	ProcessExecutableName string       `json:"process.executable.name,omitempty"`
	SpanId                string       `json:"span.id,omitempty"`
}

type dtLogContent struct {
	Output       string                 `json:"output"`
	OutputFields map[string]interface{} `json:"output_fields"`
	Tags         []string               `json:"tags,omitempty"`
}

const DynatraceContentType = "application/json; charset=utf-8"
const DynatraceEventProvider = "Khulnasoft"

// match MITRE techniques, e.g. "T1070", and sub-techniques, e.g. "T1055.008"
var MitreTechniqueRegEx = regexp.MustCompile(`T\d+\.?\d*`)

// match MITRE tactics, e.g. "mitre_execution"
var MitreTacticRegEx = regexp.MustCompile(`mitre_\w+`)

func newDynatracePayload(khulnasoftpayload types.KhulnasoftPayload) dtPayload {
	message := dtLogMessage{
		Timestamp:     khulnasoftpayload.Time.Format(time.RFC3339),
		EventId:       khulnasoftpayload.UUID,
		EventName:     khulnasoftpayload.Rule,
		EventProvider: DynatraceEventProvider,
		Severity:      khulnasoftpayload.Priority.String(),
		HostName:      khulnasoftpayload.Hostname,
		LogSource:     khulnasoftpayload.Source,
		Content: dtLogContent{
			Output:       khulnasoftpayload.Output,
			OutputFields: khulnasoftpayload.OutputFields,
			Tags:         khulnasoftpayload.Tags,
		},
	}

	// possibly map a few fields to semantic attributes
	if khulnasoftpayload.OutputFields != nil {
		for fcKey, val := range khulnasoftpayload.OutputFields {
			if val == nil {
				continue
			}

			switch fcKey {
			case "container.id":
				message.ContainerId = val.(string)
			case "container.name":
				message.ContainerName = val.(string)
			case "container.image":
				message.ContainerImageName = val.(string)
			case "k8s.ns.name", "ka.target.namespace":
				message.K8sNamespaceName = val.(string)
			case "k8s.pod.name":
				message.K8sPodName = val.(string)
			case "k8s.pod.id":
				message.K8sPodUid = val.(string)
			case "proc.name":
				message.ProcessExecutableName = val.(string)
			case "span.id":
				message.SpanId = strconv.Itoa(val.(int))
			default:
				continue
			}
		}
	}

	// map tags to MITRE technique and tactic
	for _, fcTag := range khulnasoftpayload.Tags {
		if MitreTechniqueRegEx.MatchString(fcTag) {
			message.MitreTechnique = fcTag
		} else if MitreTacticRegEx.MatchString(fcTag) {
			message.MitreTactic = fcTag
		}
	}

	return dtPayload{Payload: []dtLogMessage{message}}
}

func (c *Client) DynatracePost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.Dynatrace.Add(Total, 1)

	c.ContentType = DynatraceContentType

	err := c.Post(newDynatracePayload(khulnasoftpayload).Payload, func(req *http.Request) {
		req.Header.Set("Authorization", "Api-Token "+c.Config.Dynatrace.APIToken)
	})
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:dynatrace", "status:error"})
		c.Stats.Dynatrace.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "dynatrace", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "dynatrace"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:dynatrace", "status:ok"})
	c.Stats.Dynatrace.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "dynatrace", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "dynatrace"),
		attribute.String("status", OK)).Inc()
}
