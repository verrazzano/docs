---
title: Metrics Template Custom Resource Definition
linkTitle: MetricsTemplate CRD
weight: 2
draft: false
---

The Metrics Template CRD contains the metrics configuration for default Kubernetes workloads.
Here is the default Metrics Template that Verrazzano installs.

```
apiVersion: app.verrazzano.io/v1alpha1
kind: MetricsTemplate
metadata:
  name: standard-k8s-metrics-template
  namespace: verrazzano-system
spec:
  workloadSelector:
    apiGroups: ["apps", ""]
    apiVersions: ["v1"]
    resources: ["deployment", "statefulset", "replicaset", "pod"]
  prometheusConfig:
    targetConfigMap:
      namespace: verrazzano-system
      name: vmi-system-prometheus-config
    scrapeConfigTemplate: |
      kubernetes_sd_configs:
        - namespaces:
            names:
            - {{`{{.workload.metadata.namespace}}`}}
          role: pod
      relabel_configs:
        - action: replace
          replacement: local
          source_labels: null
          target_label: verrazzano_cluster
        - action: keep
          regex: {{`{{index .workload.metadata.labels "app.verrazzano.io/workload"}}`}};true
          source_labels:
            - __meta_kubernetes_pod_label_app_verrazzano_io_workload
            - __meta_kubernetes_pod_annotation_prometheus_io_scrape
        - action: replace
          regex: ([^:]+)(?::\d+)?;(\d+)
          replacement: $1:$2
          source_labels:
            - __address__
            - __meta_kubernetes_pod_annotation_prometheus_io_port
          target_label: __address__
        - action: replace
          regex: (.*)
          source_labels:
            - __meta_kubernetes_pod_annotation_prometheus_io_path
          target_label: __metrics_path__
        - action: replace
          regex: (.*)
          replacement: $1
          source_labels:
            - __meta_kubernetes_namespace
          target_label: namespace
        - action: labelmap
          regex: __meta_kubernetes_pod_label_(.+)
        - action: replace
          source_labels:
            - __meta_kubernetes_pod_name
          target_label: pod_name
        - action: labeldrop
          regex: (controller_revision_hash)
        - action: replace
          regex: .*/(.*)$
          replacement: $1
          source_labels:
            - name
          target_label: webapp
      {{`{{ if index .namespace.metadata.labels "istio-injection" }}`}}
      {{`{{ if eq (index .namespace.metadata.labels "istio-injection" ) "enabled" }}`}}
      scheme: https
      tls_config:
        ca_file: /etc/istio-certs/root-cert.pem
        cert_file: /etc/istio-certs/cert-chain.pem
        insecure_skip_verify: true
        key_file: /etc/istio-certs/key.pem
      {{`{{ end }}`}}
      {{`{{ end }}`}}
```

For more information on using the Metrics Template, see [Metrics Template]({{< relref "/docs/monitoring/metrics/metrics.md#metrics-template" >}}).

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
