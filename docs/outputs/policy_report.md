# Policy Report

- **Category**: Other
- **Website**: https://github.com/kubernetes-sigs/wg-policy-prototypes/tree/master/policy-report/khulnasoft-adapter

## Table of content

- [Policy Report](#policy-report)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
    - [Installing Policy Report Custom Resource Definition (CRD)](#installing-policy-report-custom-resource-definition-crd)
  - [Screenshots](#screenshots)

## Configuration

|            Setting             |            Env var             |  Default value   |                                                             Description                                                             |
| ------------------------------ | ------------------------------ | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `policyreport.enabled`         | `POLICYREPORT_ENABLED`         |                  | If true; policyreport output is **enabled**                                                                                         |
| `policyreport.kubeconfig`      | `POLICYREPORT_KUBECONFIG`      | `~/.kube/config` | Kubeconfig file to use (only if fanal is running outside the cluster)                                                       |
| `policyreport.khulnasoftnamespace`  | `POLICYREPORT_FANALNAMESPACE`  |                  | Set the namespace where Khulnasoft is running (only if fanal is running outside the cluster)                                     |
| `policyreport.maxevents`       | `POLICYREPORT_MAXEVENTS`       | `1000`           | The max number of events that can be in a policyreport                                                                              |
| `policyreport.minimumpriority` | `POLICYREPORT_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
policyreport:
  enabled: false  # if true; policyreport output is enabled
  kubeconfig: "~/.kube/config"  # kubeconfig file to use (only if fanal is running outside the cluster)
  khulnasoftnamespace: ""  # set the namespace where Khulnasoft is running (only if fanal is running outside the cluster)
  maxevents: 1000 # the max number of events that can be in a policyreport (default: 1000)
  minimumpriority: "debug" # events with a priority above this are mapped to fail in PolicyReport Summary and lower that those are mapped to warn (default="")
```

## Additional info

### Installing Policy Report Custom Resource Definition (CRD)

> [!WARNING]
This output works only for the sources `syscalls` and `k8saudit`.

> [!WARNING]
Installation of the Policy Report Custom Resource Definition (CRD) is a prerequisite for using the Policy Report output.

Information about how to find and install the CRD for the reports can be found [here](https://github.com/kubernetes-sigs/wg-policy-prototypes/tree/master/policy-report#installing). 

## Screenshots