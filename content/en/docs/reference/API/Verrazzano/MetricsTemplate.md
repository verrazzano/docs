---
title: Metrics Template
weight: 2
draft: false
---

Due to the integration of the Prometheus Operator, the Metrics Template will no longer be used to provide metrics from default Kubernetes workloads.
Instead, we recommend using [Service Monitors](https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md#servicemonitor) and [Pod Monitors](https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md#podmonitor).

For more information on setting up metrics for Kubernetes workloads, see [Verrazzano metrics]({{< relref "/docs/monitoring/metrics/metrics.md" >}}).

#### MetricsTemplate

| Field        | Type                                        | Description                                                       | Required |
|--------------|---------------------------------------------|-------------------------------------------------------------------|----------|
| `apiVersion` | string                                      | `app.verrazzano.io/v1alpha1`                                      | Yes      |
| `kind`       | string                                      | MetricsTemplate                                                   | Yes      |
| `metadata`   | ObjectMeta                                  | Refer to the Kubernetes API documentation for fields of metadata. | No       |
| `spec`       | [MetricsTemplateSpec](#metricstemplatespec) | The desired state of a metrics trait.                             | Yes      |

#### MetricsTemplateSpec
| Field              | Type                                  | Description                       | Required |
|--------------------|---------------------------------------|-----------------------------------|----------|
| `workloadSelector` | [WorkloadSelector](#workloadselector) | Selector for target workloads.    | No       |
| `prometheusConfig` | [PrometheusConfig](#prometheusconfig) | Prometheus configuration details. | No       |

#### WorkloadSelector
| Field               | Type                                                                                                       | Description                                        | Required |
|---------------------|------------------------------------------------------------------------------------------------------------|----------------------------------------------------|----------|
| `namespaceSelector` | [LabelSelector](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors) | Scopes the template to a namespace.                | No       |
| `objectSelector`    | [LabelSelector](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors) | Scopes the template to a specific workload object. | No       |
| `apiGroups`         | []string                                                                                                   | Scopes the template to given API Groups.           | No       |
| `apiVersions`       | []string                                                                                                   | Scopes the template to given API Versions.         | No       |
| `resources`         | []string                                                                                                   | Scopes the template to given API Resources.        | No       |

#### PrometheusConfig
| Field                  | Type                                | Description                                                                                                | Required |
|------------------------|-------------------------------------|------------------------------------------------------------------------------------------------------------|----------|
| `targetConfigMap`      | [TargetConfigMap](#targetconfigmap) | Identity of the ConfigMap to be updated with the scrape configuration specified in `scrapeConfigTemplate`. | Yes      |
| `scrapeConfigTemplate` | string                              | Scrape configuration template to be added to the Prometheus configuration.                                 | Yes      |

#### TargetConfigMap
| Field       | Type   | Description                                                                    | Required |
|-------------|--------|--------------------------------------------------------------------------------|----------|
| `namespace` | string | Namespace of the ConfigMap to be updated with the scrape target configuration. | Yes      |
| `name`      | string | Name of the ConfigMap to be updated with the scrape target configuration.      | Yes      |
