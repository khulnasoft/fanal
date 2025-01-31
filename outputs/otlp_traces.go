// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/outputs/otlpmetrics"
	"github.com/khulnasoft/fanal/types"
)

// Unit-testing helper
var getTracerProvider = otel.GetTracerProvider

func NewOtlpTracesClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	initClientArgs := &types.InitClientArgs{
		Config:          config,
		Stats:           stats,
		DogstatsdClient: dogstatsdClient,
		PromStats:       promStats,
		OTLPMetrics:     otlpMetrics,
		StatsdClient:    statsdClient,
	}
	otlpClient, err := NewClient("OTLPTraces", config.OTLP.Traces.Endpoint, types.CommonConfig{}, *initClientArgs)
	if err != nil {
		return nil, err
	}
	shutDownFunc, err := otlpInit(config)
	if err != nil {
		utils.Log(utils.ErrorLvl, "OLTP Traces", fmt.Sprintf("Error client creation: %v", err))
		return nil, err
	}
	utils.Log(utils.InfoLvl, "OTLP Traces", "Client created")
	otlpClient.ShutDownFunc = shutDownFunc
	return otlpClient, nil
}

// newTrace returns a new Trace object.
func (c *Client) newTrace(khulnasoftpayload types.KhulnasoftPayload) (*trace.Span, error) {
	traceID, err := generateTraceID(khulnasoftpayload)
	if err != nil {
		return nil, err
	}

	startTime := khulnasoftpayload.Time
	endTime := khulnasoftpayload.Time.Add(time.Millisecond * time.Duration(c.Config.OTLP.Traces.Duration))

	sc := trace.SpanContext{}.WithTraceID(traceID)
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	tracer := getTracerProvider().Tracer("khulnasoft-event")
	_, span := tracer.Start(
		ctx,
		khulnasoftpayload.Rule,
		trace.WithTimestamp(startTime),
		trace.WithSpanKind(trace.SpanKindServer))

	span.SetAttributes(attribute.String("uuid", khulnasoftpayload.UUID))
	span.SetAttributes(attribute.String("source", khulnasoftpayload.Source))
	span.SetAttributes(attribute.String("priority", khulnasoftpayload.Priority.String()))
	span.SetAttributes(attribute.String("rule", khulnasoftpayload.Rule))
	span.SetAttributes(attribute.String("output", khulnasoftpayload.Output))
	span.SetAttributes(attribute.String("hostname", khulnasoftpayload.Hostname))
	span.SetAttributes(attribute.StringSlice("tags", khulnasoftpayload.Tags))
	for k, v := range khulnasoftpayload.OutputFields {
		span.SetAttributes(attribute.String(k, fmt.Sprintf("%v", v)))
	}
	span.End(trace.WithTimestamp(endTime))

	if c.Config.Debug {
		utils.Log(utils.DebugLvl, c.OutputType, fmt.Sprintf("Payload generated successfully for traceid=%s", span.SpanContext().TraceID()))
	}

	return &span, nil
}

// OTLPPost generates an OTLP trace _implicitly_ via newTrace() by
// calling OTEL SDK's tracer.Start() --> span.End(), i.e. no need to explicitly
// do a HTTP POST
func (c *Client) OTLPTracesPost(khulnasoftpayload types.KhulnasoftPayload) {
	c.Stats.OTLPTraces.Add(Total, 1)

	_, err := c.newTrace(khulnasoftpayload)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:otlptraces", "status:error"})
		c.Stats.OTLPTraces.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "otlptraces", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "otlptraces"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("Error generating trace: %v", err))
		return
	}
	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:otlptraces", "status:ok"})
	c.Stats.OTLPTraces.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "otlptraces", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "otlptraces"),
		attribute.String("status", OK)).Inc()
	utils.Log(utils.InfoLvl, c.OutputType, "OK")
}

func generateTraceID(khulnasoftpayload types.KhulnasoftPayload) (trace.TraceID, error) {
	var k8sNsName, k8sPodName, containerId, evtHostname string

	if khulnasoftpayload.OutputFields["k8s.ns.name"] != nil {
		k8sNsName = khulnasoftpayload.OutputFields["k8s.ns.name"].(string)
	}
	if khulnasoftpayload.OutputFields["k8s.pod.name"] != nil {
		k8sPodName = khulnasoftpayload.OutputFields["k8s.pod.name"].(string)
	}
	if khulnasoftpayload.OutputFields["container.id"] != nil {
		containerId = khulnasoftpayload.OutputFields["container.id"].(string)
	}
	if khulnasoftpayload.OutputFields["evt.hostname"] != nil {
		evtHostname = khulnasoftpayload.OutputFields["evt.hostname"].(string)
	}

	var traceIDStr string
	if k8sNsName != "" && k8sPodName != "" {
		traceIDStr = fmt.Sprintf("%v:%v", k8sNsName, k8sPodName)
	} else if containerId != "" && containerId != "host" {
		traceIDStr = containerId
	} else if evtHostname != "" {
		traceIDStr = evtHostname
	}

	if traceIDStr == "" {
		return trace.TraceID{}, errors.New("can't find any field to generate an immutable trace id")
	}

	// Hash to return a 32 character traceID
	hash := fnv.New128a()
	hash.Write([]byte(traceIDStr))
	digest := hash.Sum(nil)
	traceIDStr = hex.EncodeToString(digest)
	return trace.TraceIDFromHex(traceIDStr)
}
