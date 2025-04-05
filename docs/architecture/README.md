# Fanal Architecture

## Overview

Fanal is a flexible alerting and notification system designed to forward security events from Khulnasoft and other monitoring systems to multiple output destinations. The system is built to be highly configurable, extensible, and resilient to failures in individual output services.

This document provides a high-level overview of Fanal's architecture, components, and design principles to help developers understand and contribute to the project.

## System Components

Fanal's architecture consists of several key components:

### HTTP Server

The HTTP server is the entry point for alerts and provides endpoints for:
- Receiving alert payloads (`/`)
- Health checks (`/health`)
- Testing (`/test`)
- Basic ping checks (`/ping`)

These endpoints are handled by corresponding functions in `handlers.go`.

### Alert Processing Pipeline

The alert processing pipeline consists of:

1. **Payload Parsing**: The incoming JSON is parsed into a `KhulnasoftPayload` structure
2. **Validation**: The payload is validated for required fields and format
3. **Enrichment**: Additional fields are added based on configuration
4. **Normalization**: Fields are standardized and formatted
5. **Output Routing**: The payload is forwarded to configured output integrations

### Output Clients

Each output destination (Slack, Elasticsearch, AWS services, etc.) has a dedicated client that:
- Formats the alert according to the specific requirements of the destination
- Handles authentication and connection management
- Provides error handling and retry logic where appropriate
- Processes alerts asynchronously to avoid blocking the main request handling

### Configuration Management

Configuration is loaded at startup from various sources and dictates:
- Which output integrations are enabled
- Authentication details for each output
- Alert filtering and routing rules
- Customization of payloads

### Metrics and Monitoring

Internal metrics are collected and exposed via:
- Prometheus metrics endpoints
- OpenTelemetry integration
- Statsd/Datadog metrics
- Internal logging

## Design Principles

Fanal is designed with the following principles in mind:

### 1. Resilience

- Output failures should not impact the main service
- All output integrations operate asynchronously
- Each integration has its own error handling

### 2. Extensibility

- New output integrations can be added with minimal changes to core code
- Common code patterns for integrations simplify adding new outputs
- Client interfaces ensure consistency across implementations

### 3. Performance

- Minimal processing on the main request path
- Efficient JSON processing with targeted field extraction
- Concurrent processing of outputs
- Careful memory management for large payloads

### 4. Security

- TLS support for all HTTP communications
- Secret management for API keys and tokens
- Input validation to prevent injection attacks
- Support for mutual TLS where appropriate

### 5. Observability

- Comprehensive metrics for all components
- Detailed error logging
- Tracing support via OpenTelemetry
- Performance benchmarking

## Technology Stack

Fanal is built using:

- Go (1.22+) for its performance, concurrency model, and standard library
- Standard HTTP server and JSON handling from the Go standard library
- External libraries for specific integrations (AWS SDK, Elasticsearch client, etc.)
- Docker for containerization and deployment

## Directory Structure

```
/
├── cmd/           # Entry points for build targets
├── internal/      # Internal packages
│   ├── pkg/       # Shared internal code
│   └── utils/     # Utility functions
├── outputs/       # Output clients for different destinations
├── types/         # Shared type definitions
├── test/          # Test code
│   ├── integration/ # Integration tests
│   └── fixtures/    # Test fixtures
├── docs/          # Documentation
│   └── architecture/ # Architecture documentation
├── .github/       # GitHub configuration
└── config/        # Configuration examples
```

## Evolution and Future Direction

The architecture is designed to evolve with:

1. **Advanced Routing** - More sophisticated routing of alerts based on content, tags, or other attributes
2. **Pluggable Architecture** - Moving towards a plugin-based system for outputs
3. **Enhanced Processing** - Adding more powerful processing capabilities for alerts
4. **Scaling** - Improvements to handle higher throughput

## Related Documentation

- [Data Flow](data_flow.md) - Detailed explanation of how data flows through the system
- [Configuration Guide](../configuration.md) - Details on configuring Fanal
- [Output Integrations](../outputs.md) - Information on available output integrations

