# StatsD

- **Category**: Metrics / Observability
- **Website**: https://github.com/statsd/statsd

## Table of content

- [StatsD](#statsd)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting            | Env var            | Default value    | Description                                                                                       |
| ------------------ | ------------------ | ---------------- | ------------------------------------------------------------------------------------------------- |
| `statsd.forwarder` | `STATSD_FORWARDER` |                  | The address for the StatsD forwarder, in the form "host:port", if not empty StatsD is **enabled** |
| `statsd.namespace` | `STATSD_NAMESPACE` | `fanal.` | A prefix for all metrics                                                                          |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
statsd:
  forwarder: "" # The address for the StatsD forwarder, in the form "host:port", if not empty StatsD is enabled
  namespace: "fanal." # A prefix for all metrics (default: "fanal.")
```

## Additional info

> [!NOTE]
This output is used to collect metrics about Khulnasoft events and Fanal outputs.

## Screenshots
