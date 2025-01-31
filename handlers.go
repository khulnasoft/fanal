// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/types"
)

const (
	testRule string = "Test rule"
	syscalls string = "syscalls"
	syscall  string = "syscall"
)

// mainHandler is Fanal main handler (default).
func mainHandler(w http.ResponseWriter, r *http.Request) {
	stats.Requests.Add("total", 1)
	nullClient.CountMetric("total", 1, []string{})

	if r.Body == nil {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		stats.Requests.Add("rejected", 1)
		promStats.Inputs.With(map[string]string{"source": "requests", "status": "rejected"}).Inc()
		otlpMetrics.Inputs.With(attribute.String("source", "requests"),
			attribute.String("status", "rejected")).Inc()
		nullClient.CountMetric("inputs.requests.rejected", 1, []string{"error:nobody"})

		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Please send with post http method", http.StatusBadRequest)
		stats.Requests.Add("rejected", 1)
		promStats.Inputs.With(map[string]string{"source": "requests", "status": "rejected"}).Inc()
		otlpMetrics.Inputs.With(attribute.String("source", "requests"),
			attribute.String("status", "rejected")).Inc()
		nullClient.CountMetric("inputs.requests.rejected", 1, []string{"error:nobody"})

		return
	}

	khulnasoftpayload, err := newKhulnasoftPayload(r.Body)
	if err != nil || !khulnasoftpayload.Check() {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		stats.Requests.Add("rejected", 1)
		promStats.Inputs.With(map[string]string{"source": "requests", "status": "rejected"}).Inc()
		otlpMetrics.Inputs.With(attribute.String("source", "requests"),
			attribute.String("status", "rejected")).Inc()
		nullClient.CountMetric("inputs.requests.rejected", 1, []string{"error:invalidjson"})

		return
	}

	nullClient.CountMetric("inputs.requests.accepted", 1, []string{})
	stats.Requests.Add("accepted", 1)
	promStats.Inputs.With(map[string]string{"source": "requests", "status": "accepted"}).Inc()
	otlpMetrics.Inputs.With(attribute.String("source", "requests"),
		attribute.String("status", "accepted")).Inc()
	forwardEvent(khulnasoftpayload)
}

// pingHandler is a simple handler to test if daemon is UP.
func pingHandler(w http.ResponseWriter, r *http.Request) {
	// #nosec G104 nothing to be done if the following fails
	w.Write([]byte("pong\n"))
}

// healthHandler is a simple handler to test if daemon is UP.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	// #nosec G104 nothing to be done if the following fails
	w.Write([]byte(`{"status": "ok"}`))
}

// testHandler sends a test event to all enabled outputs.
func testHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = io.NopCloser(bytes.NewReader([]byte(`{"output":"This is a test from fanal","source":"debug","priority":"Debug","hostname":"fanal", "rule":"Test rule","time":"` + time.Now().UTC().Format(time.RFC3339) + `","output_fields":{"proc.name":"fanal","user.name":"fanal"},"tags":["test","example"]}`)))
	mainHandler(w, r)
}

func newKhulnasoftPayload(payload io.Reader) (types.KhulnasoftPayload, error) {
	var khulnasoftpayload types.KhulnasoftPayload

	d := json.NewDecoder(payload)
	d.UseNumber()

	err := d.Decode(&khulnasoftpayload)
	if err != nil {
		return types.KhulnasoftPayload{}, err
	}

	var customFields string
	if len(config.Customfields) > 0 {
		if khulnasoftpayload.OutputFields == nil {
			khulnasoftpayload.OutputFields = make(map[string]interface{})
		}
		for key, value := range config.Customfields {
			customFields += key + "=" + value + " "
			khulnasoftpayload.OutputFields[key] = value
		}
	}

	khulnasoftpayload.Tags = append(khulnasoftpayload.Tags, config.Customtags...)

	if khulnasoftpayload.Rule == "Test rule" {
		khulnasoftpayload.Source = "internal"
	}

	if khulnasoftpayload.Source == "" {
		khulnasoftpayload.Source = syscalls
	}

	khulnasoftpayload.UUID = uuid.New().String()

	var kn, kp string
	for i, j := range khulnasoftpayload.OutputFields {
		if j != nil {
			if i == "k8s.ns.name" {
				kn = j.(string)
			}
			if i == "k8s.pod.name" {
				kp = j.(string)
			}
		}
	}

	var templatedFields string
	if len(config.Templatedfields) > 0 {
		if khulnasoftpayload.OutputFields == nil {
			khulnasoftpayload.OutputFields = make(map[string]interface{})
		}
		for key, value := range config.Templatedfields {
			tmpl, err := template.New("").Parse(value)
			if err != nil {
				utils.Log(utils.ErrorLvl, "", fmt.Sprintf("Parsing error for templated field '%v': %v", key, err))
				continue
			}
			v := new(bytes.Buffer)
			if err := tmpl.Execute(v, khulnasoftpayload.OutputFields); err != nil {
				utils.Log(utils.ErrorLvl, "", fmt.Sprintf("Parsing error for templated field '%v': %v", key, err))
			}
			templatedFields += key + "=" + v.String() + " "
			khulnasoftpayload.OutputFields[key] = v.String()
		}
	}

	if len(khulnasoftpayload.Tags) != 0 {
		sort.Strings(khulnasoftpayload.Tags)
	}

	nullClient.CountMetric("khulnasoft.accepted", 1, []string{"priority:" + khulnasoftpayload.Priority.String()})
	stats.Khulnasoft.Add(strings.ToLower(khulnasoftpayload.Priority.String()), 1)
	promLabels := map[string]string{
		"rule":         khulnasoftpayload.Rule,
		"priority_raw": strings.ToLower(khulnasoftpayload.Priority.String()),
		"priority":     strconv.Itoa(int(khulnasoftpayload.Priority)),
		"source":       khulnasoftpayload.Source,
		"k8s_ns_name":  kn,
		"k8s_pod_name": kp,
	}
	if khulnasoftpayload.Hostname != "" {
		promLabels["hostname"] = khulnasoftpayload.Hostname
	} else {
		promLabels["hostname"] = "unknown"
	}

	for key, value := range config.Customfields {
		if regPromLabels.MatchString(key) {
			promLabels[key] = value
		}
	}
	for key := range config.Templatedfields {
		if regPromLabels.MatchString(key) {
			promLabels[key] = fmt.Sprintf("%v", khulnasoftpayload.OutputFields[key])
		}
	}
	for _, i := range config.Prometheus.ExtraLabelsList {
		promLabels[strings.ReplaceAll(i, ".", "_")] = ""
		for key, value := range khulnasoftpayload.OutputFields {
			if key == i && regPromLabels.MatchString(strings.ReplaceAll(key, ".", "_")) {
				switch value.(type) {
				case string:
					promLabels[strings.ReplaceAll(key, ".", "_")] = fmt.Sprintf("%v", value)
				default:
					continue
				}
			}
		}
	}
	promStats.Khulnasoft.With(promLabels).Inc()

	// Khulnasoft OTLP metric
	hostname := khulnasoftpayload.Hostname
	if hostname == "" {
		hostname = "unknown"
	}
	attrs := []attribute.KeyValue{
		attribute.String("source", khulnasoftpayload.Source),
		attribute.String("priority", khulnasoftpayload.Priority.String()),
		attribute.String("rule", khulnasoftpayload.Rule),
		attribute.String("hostname", hostname),
		attribute.StringSlice("tags", khulnasoftpayload.Tags),
	}

	for key, value := range config.Customfields {
		if regOTLPMetricsAttributes.MatchString(key) {
			attrs = append(attrs, attribute.String(key, value))
		}
	}
	for _, attr := range config.OTLP.Metrics.ExtraAttributesList {
		attrName := strings.ReplaceAll(attr, ".", "_")
		attrValue := ""
		for key, val := range khulnasoftpayload.OutputFields {
			if key != attr {
				continue
			}
			if keyName := strings.ReplaceAll(key, ".", "_"); !regOTLPMetricsAttributes.MatchString(keyName) {
				continue
			}
			// Notice: Don't remove the _ for the second return value, otherwise will panic if it can convert the value
			// to string
			attrValue, _ = val.(string)
			break
		}
		attrs = append(attrs, attribute.String(attrName, attrValue))
	}
	otlpMetrics.Khulnasoft.With(attrs...).Inc()

	if config.BracketReplacer != "" {
		for i, j := range khulnasoftpayload.OutputFields {
			if strings.Contains(i, "[") {
				khulnasoftpayload.OutputFields[strings.ReplaceAll(strings.ReplaceAll(i, "]", ""), "[", config.BracketReplacer)] = j
				delete(khulnasoftpayload.OutputFields, i)
			}
		}
	}

	if config.OutputFieldFormat != "" && regOutputFormat.MatchString(khulnasoftpayload.Output) {
		outputElements := strings.Split(khulnasoftpayload.Output, " ")
		if len(outputElements) >= 3 {
			t := strings.TrimSuffix(outputElements[0], ":")
			p := cases.Title(language.English).String(khulnasoftpayload.Priority.String())
			o := strings.Join(outputElements[2:], " ")
			n := config.OutputFieldFormat
			n = strings.ReplaceAll(n, "<timestamp>", t)
			n = strings.ReplaceAll(n, "<priority>", p)
			n = strings.ReplaceAll(n, "<output>", o)
			n = strings.ReplaceAll(n, "<custom_fields>", strings.TrimSuffix(customFields, " "))
			n = strings.ReplaceAll(n, "<templated_fields>", strings.TrimSuffix(templatedFields, " "))
			n = strings.ReplaceAll(n, "<tags>", strings.Join(khulnasoftpayload.Tags, ","))
			n = strings.TrimSuffix(n, " ")
			n = strings.TrimSuffix(n, "( )")
			n = strings.TrimSuffix(n, "()")
			n = strings.TrimSuffix(n, " ")
			khulnasoftpayload.Output = n
		}
	}

	if len(khulnasoftpayload.String()) > 4096 {
		for i, j := range khulnasoftpayload.OutputFields {
			switch l := j.(type) {
			case string:
				if len(l) > 512 {
					k := j.(string)[:507] + "[...]"
					khulnasoftpayload.Output = strings.ReplaceAll(khulnasoftpayload.Output, j.(string), k)
					khulnasoftpayload.OutputFields[i] = k
				}
			}
		}
	}

	if config.Debug {
		utils.Log(utils.DebugLvl, "", fmt.Sprintf("Khulnasoft's payload : %v", khulnasoftpayload.String()))
	}

	return khulnasoftpayload, nil
}

func forwardEvent(khulnasoftpayload types.KhulnasoftPayload) {
	if config.Slack.WebhookURL != "" && (khulnasoftpayload.Priority >= types.Priority(config.Slack.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go slackClient.SlackPost(khulnasoftpayload)
	}

	if config.Cliq.WebhookURL != "" && (khulnasoftpayload.Priority >= types.Priority(config.Cliq.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go cliqClient.CliqPost(khulnasoftpayload)
	}

	if config.Rocketchat.WebhookURL != "" && (khulnasoftpayload.Priority >= types.Priority(config.Rocketchat.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go rocketchatClient.RocketchatPost(khulnasoftpayload)
	}

	if config.Mattermost.WebhookURL != "" && (khulnasoftpayload.Priority >= types.Priority(config.Mattermost.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go mattermostClient.MattermostPost(khulnasoftpayload)
	}

	if config.Teams.WebhookURL != "" && (khulnasoftpayload.Priority >= types.Priority(config.Teams.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go teamsClient.TeamsPost(khulnasoftpayload)
	}

	if config.Webex.WebhookURL != "" && (khulnasoftpayload.Priority >= types.Priority(config.Webex.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go webexClient.WebexPost(khulnasoftpayload)
	}

	if config.Datadog.APIKey != "" && (khulnasoftpayload.Priority >= types.Priority(config.Datadog.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go datadogClient.DatadogPost(khulnasoftpayload)
	}

	if config.DatadogLogs.APIKey != "" && (khulnasoftpayload.Priority >= types.Priority(config.DatadogLogs.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go datadogLogsClient.DatadogLogsPost(khulnasoftpayload)
	}

	if config.Discord.WebhookURL != "" && (khulnasoftpayload.Priority >= types.Priority(config.Discord.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go discordClient.DiscordPost(khulnasoftpayload)
	}

	if len(config.Alertmanager.HostPort) != 0 && (khulnasoftpayload.Priority >= types.Priority(config.Alertmanager.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		for _, i := range alertmanagerClients {
			go i.AlertmanagerPost(khulnasoftpayload)
		}
	}

	if config.Elasticsearch.HostPort != "" && (khulnasoftpayload.Priority >= types.Priority(config.Elasticsearch.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go elasticsearchClient.ElasticsearchPost(khulnasoftpayload)
	}

	if config.Quickwit.HostPort != "" && (khulnasoftpayload.Priority >= types.Priority(config.Quickwit.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go quickwitClient.QuickwitPost(khulnasoftpayload)
	}

	if config.Influxdb.HostPort != "" && (khulnasoftpayload.Priority >= types.Priority(config.Influxdb.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go influxdbClient.InfluxdbPost(khulnasoftpayload)
	}

	if config.Loki.HostPort != "" && (khulnasoftpayload.Priority >= types.Priority(config.Loki.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go lokiClient.LokiPost(khulnasoftpayload)
	}

	if config.SumoLogic.ReceiverURL != "" && (khulnasoftpayload.Priority >= types.Priority(config.SumoLogic.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go sumologicClient.SumoLogicPost(khulnasoftpayload)
	}

	if config.Nats.HostPort != "" && (khulnasoftpayload.Priority >= types.Priority(config.Nats.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go natsClient.NatsPublish(khulnasoftpayload)
	}

	if config.Stan.HostPort != "" && config.Stan.ClusterID != "" && config.Stan.ClientID != "" && (khulnasoftpayload.Priority >= types.Priority(config.Stan.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go stanClient.StanPublish(khulnasoftpayload)
	}

	if config.AWS.Lambda.FunctionName != "" && (khulnasoftpayload.Priority >= types.Priority(config.AWS.Lambda.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go awsClient.InvokeLambda(khulnasoftpayload)
	}

	if config.AWS.SQS.URL != "" && (khulnasoftpayload.Priority >= types.Priority(config.AWS.SQS.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go awsClient.SendMessage(khulnasoftpayload)
	}

	if config.AWS.SNS.TopicArn != "" && (khulnasoftpayload.Priority >= types.Priority(config.AWS.SNS.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go awsClient.PublishTopic(khulnasoftpayload)
	}

	if config.AWS.CloudWatchLogs.LogGroup != "" && (khulnasoftpayload.Priority >= types.Priority(config.AWS.CloudWatchLogs.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go awsClient.SendCloudWatchLog(khulnasoftpayload)
	}

	if config.AWS.S3.Bucket != "" && (khulnasoftpayload.Priority >= types.Priority(config.AWS.S3.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go awsClient.UploadS3(khulnasoftpayload)
	}

	if (config.AWS.SecurityLake.Bucket != "" && config.AWS.SecurityLake.Region != "" && config.AWS.SecurityLake.AccountID != "" && config.AWS.SecurityLake.Prefix != "") && (khulnasoftpayload.Priority >= types.Priority(config.AWS.SecurityLake.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go awsClient.EnqueueSecurityLake(khulnasoftpayload)
	}

	if config.AWS.Kinesis.StreamName != "" && (khulnasoftpayload.Priority >= types.Priority(config.AWS.Kinesis.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go awsClient.PutRecord(khulnasoftpayload)
	}

	if config.SMTP.HostPort != "" && (khulnasoftpayload.Priority >= types.Priority(config.SMTP.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go smtpClient.SendMail(khulnasoftpayload)
	}

	if config.Opsgenie.APIKey != "" && (khulnasoftpayload.Priority >= types.Priority(config.Opsgenie.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go opsgenieClient.OpsgeniePost(khulnasoftpayload)
	}

	if config.Webhook.Address != "" && (khulnasoftpayload.Priority >= types.Priority(config.Webhook.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go webhookClient.WebhookPost(khulnasoftpayload)
	}

	if config.NodeRed.Address != "" && (khulnasoftpayload.Priority >= types.Priority(config.NodeRed.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go noderedClient.NodeRedPost(khulnasoftpayload)
	}

	if config.CloudEvents.Address != "" && (khulnasoftpayload.Priority >= types.Priority(config.CloudEvents.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go cloudeventsClient.CloudEventsSend(khulnasoftpayload)
	}

	if config.Azure.EventHub.Name != "" && (khulnasoftpayload.Priority >= types.Priority(config.Azure.EventHub.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go azureClient.EventHubPost(khulnasoftpayload)
	}

	if config.GCP.PubSub.ProjectID != "" && config.GCP.PubSub.Topic != "" && (khulnasoftpayload.Priority >= types.Priority(config.GCP.PubSub.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go gcpClient.GCPPublishTopic(khulnasoftpayload)
	}

	if config.GCP.CloudFunctions.Name != "" && (khulnasoftpayload.Priority >= types.Priority(config.GCP.CloudFunctions.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go gcpClient.GCPCallCloudFunction(khulnasoftpayload)
	}

	if config.GCP.CloudRun.Endpoint != "" && (khulnasoftpayload.Priority >= types.Priority(config.GCP.CloudRun.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go gcpCloudRunClient.CloudRunFunctionPost(khulnasoftpayload)
	}

	if config.GCP.Storage.Bucket != "" && (khulnasoftpayload.Priority >= types.Priority(config.GCP.Storage.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go gcpClient.UploadGCS(khulnasoftpayload)
	}

	if config.Googlechat.WebhookURL != "" && (khulnasoftpayload.Priority >= types.Priority(config.Googlechat.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go googleChatClient.GooglechatPost(khulnasoftpayload)
	}

	if config.Kafka.HostPort != "" && (khulnasoftpayload.Priority >= types.Priority(config.Kafka.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go kafkaClient.KafkaProduce(khulnasoftpayload)
	}

	if config.KafkaRest.Address != "" && (khulnasoftpayload.Priority >= types.Priority(config.KafkaRest.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go kafkaRestClient.KafkaRestPost(khulnasoftpayload)
	}

	if config.Pagerduty.RoutingKey != "" && (khulnasoftpayload.Priority >= types.Priority(config.Pagerduty.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go pagerdutyClient.PagerdutyPost(khulnasoftpayload)
	}

	if config.Kubeless.Namespace != "" && config.Kubeless.Function != "" && (khulnasoftpayload.Priority >= types.Priority(config.Kubeless.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go kubelessClient.KubelessCall(khulnasoftpayload)
	}

	if config.Openfaas.FunctionName != "" && (khulnasoftpayload.Priority >= types.Priority(config.Openfaas.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go openfaasClient.OpenfaasCall(khulnasoftpayload)
	}

	if config.Tekton.EventListener != "" && (khulnasoftpayload.Priority >= types.Priority(config.Tekton.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go tektonClient.TektonPost(khulnasoftpayload)
	}

	if config.Rabbitmq.URL != "" && config.Rabbitmq.Queue != "" && (khulnasoftpayload.Priority >= types.Priority(config.Openfaas.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go rabbitmqClient.Publish(khulnasoftpayload)
	}

	if config.Wavefront.EndpointHost != "" && config.Wavefront.EndpointType != "" && (khulnasoftpayload.Priority >= types.Priority(config.Wavefront.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go wavefrontClient.WavefrontPost(khulnasoftpayload)
	}

	if config.Grafana.HostPort != "" && (khulnasoftpayload.Priority >= types.Priority(config.Grafana.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go grafanaClient.GrafanaPost(khulnasoftpayload)
	}

	if config.GrafanaOnCall.WebhookURL != "" && (khulnasoftpayload.Priority >= types.Priority(config.GrafanaOnCall.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go grafanaOnCallClient.GrafanaOnCallPost(khulnasoftpayload)
	}

	if config.WebUI.URL != "" {
		go webUIClient.WebUIPost(khulnasoftpayload)
	}

	if config.Fission.Function != "" && (khulnasoftpayload.Priority >= types.Priority(config.Fission.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go fissionClient.FissionCall(khulnasoftpayload)
	}
	if config.PolicyReport.Enabled && (khulnasoftpayload.Priority >= types.Priority(config.PolicyReport.MinimumPriority)) {
		if khulnasoftpayload.Source == syscalls || khulnasoftpayload.Source == syscall || khulnasoftpayload.Source == "k8saudit" {
			go policyReportClient.UpdateOrCreatePolicyReport(khulnasoftpayload)
		}
	}

	if config.Yandex.S3.Bucket != "" && (khulnasoftpayload.Priority >= types.Priority(config.Yandex.S3.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go yandexClient.UploadYandexS3(khulnasoftpayload)
	}

	if config.Yandex.DataStreams.StreamName != "" && (khulnasoftpayload.Priority >= types.Priority(config.Yandex.DataStreams.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go yandexClient.UploadYandexDataStreams(khulnasoftpayload)
	}

	if config.Syslog.Host != "" && (khulnasoftpayload.Priority >= types.Priority(config.Syslog.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go syslogClient.SyslogPost(khulnasoftpayload)
	}

	if config.MQTT.Broker != "" && (khulnasoftpayload.Priority >= types.Priority(config.MQTT.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go mqttClient.MQTTPublish(khulnasoftpayload)
	}

	if config.Zincsearch.HostPort != "" && (khulnasoftpayload.Priority >= types.Priority(config.Zincsearch.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go zincsearchClient.ZincsearchPost(khulnasoftpayload)
	}

	if config.Gotify.HostPort != "" && (khulnasoftpayload.Priority >= types.Priority(config.Gotify.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go gotifyClient.GotifyPost(khulnasoftpayload)
	}

	if config.Spyderbat.OrgUID != "" && (khulnasoftpayload.Priority >= types.Priority(config.Spyderbat.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go spyderbatClient.SpyderbatPost(khulnasoftpayload)
	}

	if config.TimescaleDB.Host != "" && (khulnasoftpayload.Priority >= types.Priority(config.TimescaleDB.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go timescaleDBClient.TimescaleDBPost(khulnasoftpayload)
	}

	if config.Redis.Address != "" && (khulnasoftpayload.Priority >= types.Priority(config.Redis.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go redisClient.RedisPost(khulnasoftpayload)
	}

	if config.Telegram.ChatID != "" && config.Telegram.Token != "" && (khulnasoftpayload.Priority >= types.Priority(config.Telegram.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go telegramClient.TelegramPost(khulnasoftpayload)
	}

	if config.N8N.Address != "" && (khulnasoftpayload.Priority >= types.Priority(config.N8N.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go n8nClient.N8NPost(khulnasoftpayload)
	}

	if config.OpenObserve.HostPort != "" && (khulnasoftpayload.Priority >= types.Priority(config.OpenObserve.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go openObserveClient.OpenObservePost(khulnasoftpayload)
	}

	if config.Dynatrace.APIToken != "" && config.Dynatrace.APIUrl != "" && (khulnasoftpayload.Priority >= types.Priority(config.Dynatrace.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go dynatraceClient.DynatracePost(khulnasoftpayload)
	}

	if config.OTLP.Traces.Endpoint != "" && (khulnasoftpayload.Priority >= types.Priority(config.OTLP.Traces.MinimumPriority)) && (khulnasoftpayload.Source == syscall || khulnasoftpayload.Source == syscalls) {
		go otlpTracesClient.OTLPTracesPost(khulnasoftpayload)
	}

	if config.Talon.Address != "" && (khulnasoftpayload.Priority >= types.Priority(config.Talon.MinimumPriority) || khulnasoftpayload.Rule == testRule) {
		go talonClient.TalonPost(khulnasoftpayload)
	}
}
