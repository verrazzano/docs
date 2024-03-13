---
title: "Prometheus"
weight: 1
draft: false
---
This document shows you how to install Prometheus on OCNE.

## Components
Verrazzano supports the following monitoring components.

### Prometheus Operator, Prometheus, Alertmanager
Verrazzano installs Prometheus Operator, Prometheus, and Alertmanager using a customized version of the Prometheus Community kube-prometheus-stack Helm chart. Prometheus Operator acts on custom resources to configure Prometheus and Alertmanager instances, and metrics scrape configurations.

You specify chart overrides for these components in the Verrazzano custom resource under `.spec.components.prometheusOperator.overrides`. The upstream kube-prometheus-stack Helm chart defines chart dependencies for kube-state-metrics, Node Exporter, and Grafana. However, the Verrazzano customized chart removes those dependencies and Verrazzano installs those components separately.

### Node Exporter
Verrazzano installs Node Exporter using a customized version of the Prometheus Community prometheus-node-exporter Helm chart. You specify chart overrides for Node Exporter in the Verrazzano custom resource under `.spec.components.prometheusNodeExporter.overrides`.

### kube-state-metrics
Verrazzano installs kube-state-metrics using a customized version of the Prometheus Community kube-state-metrics Helm chart. You specify chart overrides for kube-state-metrics in the Verrazzano custom resource under `.spec.components.kubeStateMetrics.overrides`.

### Prometheus Adapter
Verrazzano installs Prometheus Adapter using a customized version of the Prometheus Community prometheus-adapter Helm chart. You specify chart overrides for Prometheus Adapter in the Verrazzano custom resource under `.spec.components.prometheusAdapter.overrides`.

### Grafana
Verrazzano does not use a Helm chart to install Grafana. As a result, there is no overrides field in the Grafana section of the Verrazzano custom resource. You can customize the Grafana instance using a limited set of configuration parameters available under `.spec.components.grafana` in the Verrazzano custom resource.

## Verrazzano chart overrides

Verrazzano applies a set of default chart overrides when installing components. The overrides for monitoring components generally fall into the following categories.

### Images
Verrazzano overrides image registries, repositories, and image tags to install Oracle built-from-source images. Registry overrides are also applied when installing Verrazzano from a private registry (for example, in a disconnected network environment).

### Pod and container security
Verrazzano overrides certain pod and container security settings to enhance the security of applications running in the cluster. For example, privilege escalation is disabled in pods to mitigate escalation attacks in a cluster.

### Istio configuration
Verrazzano overrides Istio settings so that the monitoring components themselves do not run in the Istio mesh. However, Prometheus may need to be able to scrape applications running both in the mesh and outside the mesh. Verrazzano overrides Prometheus settings to mount CA certificates that allow Prometheus to scrape applications in the mesh.

### Metric relabeling
Verrazzano overrides chart values to add metric relabelings. The relabelings add a `verrazzano_cluster` label to all metrics. The relabeling configuration also adds a `verrazzano_component` label to label metrics for Verrazzano system components.

### Other
Verrazzano overrides chart values for various other settings, including specifying memory and storage and requests, namespace and label configuration for discovering ServiceMonitor and PodMonitor resources, and such.

## Migration steps

Follow these steps to install (or upgrade) and configure monitoring components. The result should be a cluster running a monitoring stack that achieves near-equivalent functionality compared to the Verrazzano-installed monitoring stack.

### Install from the application catalog

Monitoring components are installed using the OCNE Application Catalog. The first step is to add the Application Catalog Helm repository to the cluster.

{{< clipboard >}}
<div class="highlight">

```
$ helm repo add ocne-app-catalog https://ocne-app-catalog-url
$ helm repo update
```
</div>
{{< /clipboard >}}

Next, install the Helm charts.

#### Install or upgrade the kube-prometheus-stack Helm chart

The following example `helm` command installs Prometheus Operator, Prometheus, Alertmanager, and kube-state-metrics in the `monitoring` namespace. Monitoring components can be installed in any namespace as long as the same namespace is used consistently. This example assumes that you are using Helm version 3.2.0 or later.

{{< clipboard >}}
<div class="highlight">

```
$ helm upgrade --install prometheus-operator ocne-app-catalog/kube-prometheus-stack -n monitoring --create-namespace
```
</div>
{{< /clipboard >}}

Optionally, provide overrides when installing. The following recipes give examples of changing the configuration using Helm overrides.

**NOTE**: Grafana is disabled by default when installing kube-prometheus-stack from the Application Catalog, but Grafana can be enabled by providing a `grafana.enabled=true` Helm override.

#### Install or upgrade the prometheus-adapter Helm chart

To install or upgrade the Prometheus Adapter:

{{< clipboard >}}
<div class="highlight">

```
$ helm upgrade --install prometheus-adapter ocne-app-catalog/prometheus-adapter -n monitoring --create-namespace
```
</div>
{{< /clipboard >}}

Optionally, provide overrides when installing. The following recipes give examples of changing the configuration using Helm overrides.

#### Helm override recipes

The following recipes provide example overrides for altering the default configuration settings for monitoring components.

##### Common workarounds

When installing the kube-prometheus-stack Helm chart, the Prometheus Operator default behavior is to discover monitors that have a "release" label. However, the Grafana Helm chart does not set that label on the Grafana ServiceMonitor. The out-of-the-box installation results in no scraping of Grafana metrics. To configure Prometheus Operator to discover all PodMonitor and ServiceMonitor resources, regardless of release label, set the following Helm overrides.

**k-p-s_common_overrides.yaml**
{{< clipboard >}}
<div class="highlight">

```
prometheus:
  prometheusSpec:
    serviceMonitorSelectorNilUsesHelmValues: false
    podMonitorSelectorNilUsesHelmValues: false
```
</div>
{{< /clipboard >}}

##### Install from a private registry
To install using a private registry (for example, in a disconnected environment), you must override Helm values to change the image registry settings for all images. For example, to install kube-prometheus-stack from a private registry at `myprivreg.com`, create an overrides file with the following content and specify it using the `-f` option when running `helm upgrade --install`.

**k-p-s_privreg_overrides.yaml**
{{< clipboard >}}
<div class="highlight">

```
prometheusOperator:
  image:
    registry: myprivreg.com
  admissionWebhooks:
    patch:
      image:
        registry: myprivreg.com
  prometheusConfigReloader:
    image:
      registry: myprivreg.com
alertmanager:
  alertmanagerSpec:
    image:
      registry: myprivreg.com
prometheus:
  prometheusSpec:
    image:
      registry: myprivreg.com
grafana:
  image:
    repository: myprivreg.com/grafana
prometheus-node-exporter:
  image:
    registry: myprivreg.com
kube-state-metrics:
  image:
    registry: myprivreg.com
```
</div>
{{< /clipboard >}}

To install prometheus-adapter from a private registry at `myprivreg.com`, create an overrides file with the following content and specify it on the `helm upgrade` command.

**p-a_privreg_overrides.yaml**
{{< clipboard >}}
<div class="highlight">

```
image:
  repository: myprivreg.com/prometheus-adapter
```
</div>
{{< /clipboard >}}

##### Configure pod and container security

Override pod and container security default settings to limit actions that pods and containers can perform in the cluster. These settings allow pods and containers to perform only operations that are needed for them to operate successfully, and mitigate security vulnerabilities, such as privilege escalation. For example, apply the following overrides when installing the kube-prometheus-stack Helm chart.

**k-p-s_sec_overrides.yaml**
{{< clipboard >}}
<div class="highlight">

```
prometheusOperator:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containerSecurityContext:
    privileged: false
    capabilities:
      drop:
        - ALL
prometheus:
  prometheusSpec:
    securityContext:
      fsGroup: 65534
      runAsGroup: 65534
      runAsNonRoot: true
      runAsUser: 65534
      seccompProfile:
        type: RuntimeDefault
alertmanager:
  alertmanagerSpec:
    securityContext:
      fsGroup: 65534
      runAsGroup: 65534
      runAsNonRoot: true
      runAsUser: 65534
      seccompProfile:
        type: RuntimeDefault
kube-state-metrics:
  containerSecurityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop:
        - ALL
    privileged: false
    readOnlyRootFilesystem: true
prometheus-node-exporter:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containerSecurityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop:
        - ALL
    privileged: false
    readOnlyRootFilesystem: true
grafana:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containerSecurityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop:
        - ALL
    privileged: false
```
</div>
{{< /clipboard >}}

The default values in the prometheus-adapter Helm chart are sufficient, so no additional overrides are required.

##### Configure Istio

When running monitoring components in a cluster that also has Istio installed, the monitoring components need to be configured as follows:

1. All of the monitoring components are configured to run outside of the Istio mesh. The Prometheus pod is configured for Istio sidecar injection so that Istio adds the Istio CA certificates to the Prometheus pod, but all of the outbound traffic is configured to bypass the Istio Envoy proxy sidecar. This configuration allows Prometheus to scrape pods that are both in and out of the mesh. If all pods that are to be scraped are inside the mesh, then this requirement can be dropped.
1. The Prometheus container needs to mount the Istio CA certificates. Istio will automatically add its certificates when Istio sidecar injection is enabled. This allows Prometheus to scrape pods in the mesh using TLS.

When installing the kube-prometheus-stack Helm chart, apply the following overrides.

{{< clipboard >}}
<div class="highlight">

```
prometheusOperator:
  podLabels:
    sidecar.istio.io/inject: "false"
prometheus:
  prometheusSpec:
    podMetadata:
      labels:
        sidecar.istio.io/inject: "true"
      annotations:
        proxy.istio.io/config: '{"proxyMetadata":{ "OUTPUT_CERTS": "/etc/istio-output-certs"}}'
        sidecar.istio.io/userVolumeMount: '[{"name": "istio-certs-dir", "mountPath": "/etc/istio-output-certs"}]'
        traffic.sidecar.istio.io/excludeOutboundIPRanges: 0.0.0.0/0
    volumeMounts:
    - name: istio-certs-dir
      mountPath: /etc/istio-certs
    volumes:
    - name: istio-certs-dir
      emptyDir:
        medium: Memory
alertmanager:
  alertmanagerSpec:
    podMetadata:
      labels:
        sidecar.istio.io/inject: "false"
kube-state-metrics:
  customLabels:
    sidecar.istio.io/inject: "false"
prometheus-node-exporter:
   podLabels:
    sidecar.istio.io/inject: "false"
grafana:
   podLabels:
    sidecar.istio.io/inject: "false"
```
</div>
{{< /clipboard >}}

When installing the prometheus-adapter Helm chart, apply the following overrides.

{{< clipboard >}}
<div class="highlight">

```
customLabels:
  sidecar.istio.io/inject: "false"
```
</div>
{{< /clipboard >}}

##### Configure storage and resource limits and requests

Specify overrides to change the default resource (storage, CPU, memory, and such) requests and limits. For example, to update resource requests for Prometheus, create the following overrides file and provide the file using the `-f` option when running `helm upgrade --install`. Note that the values shown here are also the default values used by Verrazzano when installing a Verrazzano custom resource configured with the `prod` profile.

**resource_overrides.yaml**
{{< clipboard >}}
<div class="highlight">

```
prometheus:
  prometheusSpec:
    storageSpec:
      volumeClaimTemplate:
        spec:
          resources:
            requests:
              storage: 50Gi
    resources:
      requests:
        memory: 128Mi
```
</div>
{{< /clipboard >}}
