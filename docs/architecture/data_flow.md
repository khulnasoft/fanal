# Fanal Data Flow

This document describes the flow of data through the Fanal system, from the receipt of an alert to its delivery to configured output destinations.

## Alert Flow Overview

```
┌─────────────┐     ┌───────────────┐     ┌─────────────────┐     ┌─────────────┐
│             │     │               │     │                 │     │             │
│ HTTP Server │────▶│ Alert Parsing │────▶│ Alert Processing│────▶│ Output Routing │
│             │     │               │     │                 │     │             │
└─────────────┘     └───────────────┘     └─────────────────┘     └─────────────┘
                                                                        │
                                                                        ▼
                                                              ┌─────────────────────┐
                                                              │                     │
                                                              │  Output Clients     │
                                                              │                     │
                                                              └─────────────────────┘
                                                                        │
                                                                        ▼
                     ┌───────────────┐     ┌───────────────┐     ┌─────────────────┐
                     │  Messaging    │     │   Storage     │     │  Notification   │
                     │  Systems      │     │   Systems     │     │  Systems        │
                     │ (Kafka, NATS) │     │ (Elasticsearch)│     │ (Slack, Email) │
                     └───────────────┘     └───────────────┘     └─────────────────┘
```

## Detailed Data Flow

### 1. HTTP Request Processing

Alert data is received via HTTP POST to the main endpoint (`/`). The `mainHandler` function handles this request:

1. Validates that the request has a body and uses the POST method
2. Captures request metrics
3. Passes the request body to the parser

### 2. Payload Parsing

The `newKhulnasoftPayload` function in `handlers.go` processes the incoming JSON:

1. Decodes the JSON into a `KhulnasoftPayload` structure
2. Validates required fields
3. Adds custom fields from configuration
4. Adds custom tags from configuration
5. Processes templated fields (if configured)
6. Handles special cases like bracket replacement and output formatting
7. Generates a UUID for the event
8. Records metrics about the alert

### 3. Alert Processing

Processing includes:

1. **Normalization** - Standardizing field names and formats
2. **Enrichment** - Adding metadata from configuration
3. **Transformation** - Applying output format templates
4. **Size Management** - Truncating large fields if necessary

### 4. Output Routing

The `forwardEvent` function routes the alert to appropriate outputs:

1. For each configured output, checks if the alert meets minimum priority requirements
2. Launches a goroutine to send the alert to each eligible output
3. Uses non-blocking sends to ensure main processing continues even if an output is slow

### 5. Output Client Processing

Each output client:

1. Formats the alert according to the destination's requirements
2. Authenticates with the destination service
3. Sends the alert using appropriate protocol (HTTP, SMTP, etc.)
4. Handles errors and retries where appropriate
5. Records metrics about the send success/failure

## Integration Patterns

Fanal uses several patterns for integrating with external systems:

### HTTP Webhook Pattern

Used for services like Slack, Discord, and custom webhooks:

1. Alert is formatted as JSON or other format as required
2. HTTP POST request is sent to configured URL
3. Headers and authentication are added as needed
4. Response is checked for success/failure

```go
// Example flow for webhook integration
formatted := formatAlertForWebhook(alert)
resp, err := httpClient.Post(webhookURL, "application/json", formatted)
// Handle response
```

### Message Queue Pattern

Used for services like Kafka, NATS, and RabbitMQ:

1. Alert is serialized for the specific queue system
2. Connection is established (or reused from connection pool)
3. Message is published to configured topic/queue
4. Delivery confirmation is processed if available

```go
// Example flow for message queue integration
serialized := serializeForQueue(alert)
err := producer.Publish(topic, serialized)
// Handle confirmation/error
```

### Storage System Pattern

Used for services like Elasticsearch, S3, and databases:

1. Alert is transformed into appropriate document format
2. Connection is established to storage service
3. Document is indexed/stored with appropriate metadata
4. Confirmation of storage is processed

```go
// Example flow for storage integration
document := transformToDocument(alert)
resp, err := client.Index(indexName, document)
// Handle confirmation/error
```

### Cloud Function Pattern

Used for serverless integrations like AWS Lambda, Google Cloud Functions:

1. Alert is serialized as input for function
2. Function is invoked with appropriate authentication
3. Response from function is processed if needed

```go
// Example flow for cloud function integration
input := prepareInputForFunction(alert)
result, err := functionClient.Invoke(functionName, input)
// Handle result/error
```

## Concurrency Model

Fanal uses Go's concurrency model to ensure efficient processing:

1. Each output send operation runs in a separate goroutine
2. This allows outputs to process in parallel
3. Slow or failing outputs don't block other outputs
4. The main HTTP handler can return quickly

## Error Handling

Error handling varies by integration type:

1. **Non-critical errors** (single output failure) are logged but don't affect other processing
2. **Retry logic** is implemented for some integrations where appropriate
3. **Circuit breaking** can be implemented for repeatedly failing services
4. **Metrics** are recorded for all errors to track reliability

## Performance Considerations

Several optimizations ensure efficient data flow:

1. **JSON processing** uses streaming parsers to minimize memory usage
2. **Connection pooling** reduces overhead for repeated connections
3. **Payload size limits** prevent excessive memory usage
4. **Asynchronous processing** ensures the main thread isn't blocked

## Configuration Impact on Data Flow

Configuration significantly affects data flow:

1. **Minimum priority** settings filter which alerts go to which outputs
2. **Custom fields** and **templated fields** modify the payload
3. **Format templates** change how data is presented
4. **Timeouts** and **retry settings** affect delivery reliability

## Testing the Data Flow

The data flow can be tested using:

1. The `/test` endpoint, which generates a test alert
2. Integration tests that verify the entire pipeline
3. Benchmarks that measure performance of critical paths

