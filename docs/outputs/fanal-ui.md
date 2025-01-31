# Fanal-UI

- **Category**: Metrics / Observability
- **Website**: https://github.com/khulnasoft/fanal-ui

## Table of content

- [Fanal-UI](#fanal-ui)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting     | Env var     | Default value | Description                                          |
| ----------- | ----------- | ------------- | ---------------------------------------------------- |
| `webui.url` | `WEBUI_URL` |               | WebUI URL, if not empty, WebUI output is **enabled** |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
webui:
  url: "" # WebUI URL, if not empty, WebUI output is enabled
```

## Additional info

## Screenshots

![fanal-ui dashboard](images/fanal-ui_dashboard.png)
![fanal-ui events](images/fanal-ui_events.png)
