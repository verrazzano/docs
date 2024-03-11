---
title: "Fluent Operator and Fluent Bit"
weight: 1
draft: false
---
This document shows you how to install Fluent Operator and Fluent Bit on OCNE.

## Verrazzano background
Fluentd is the default logging agent in Verrazzano, which runs as a DaemonSet that collects, processes, and sends logs to log stores. When Verrazzano is installed, Fluentd is installed by default.
Starting in Verrazzano 1.6, users have the option to replace Fluentd DaemonSet with Fluent Bit DaemonSet that gets installed using Fluent Operator.

Verrazzano includes Fluent Operator as an optional component. When enabled, the operator is installed in the cluster in the `verrazzano-system` namespace and creates the Fluent Bit DaemonSet in the same namespace, using the required custom resources. For a list of custom resources that the operator supports to configure Fluent Bit, see https://github.com/fluent/fluent-operator?tab=readme-ov-file#fluent-bit. All the CRDs with the prefix `Cluster` are cluster-wide configurations that you can use to configure all the cluster logs.

Like cluster-wide resources, the operator comes with namespaced resources, which when created will process logs from the namespace in which these resources exist. The namespaced and cluster-wide configurations will run in conjunction and complement each other. Creating a namespaced resource doesn’t override an existing cluster-wide resource.

## Fluent Operator with OCNE 2.0
Fluentd DaemonSet is not going to be an option in OCNE 2.0. Customers are advised to install Fluent Operator to configure and manage Fluent Bit DaemonSet.

### Install Fluent Operator using Helm
Fluent Operator is installed using the OCNE Application Catalog. The first step is to add the Application Catalog Helm repository to the cluster.
{{< clipboard >}}
<div class="highlight">

```
$ helm repo add ocne-app-catalog https://ocne-app-catalog-url
$ helm repo update
```
</div>
{{< /clipboard >}}

Next, install the Helm charts.

#### Install or upgrade the fluent-operator Helm chart

The following example `helm` command installs Fluent Operator and Fluent Bit in the `logging` namespace. Fluent Operator and Fluent Bit can be installed in any namespace as long as the same namespace is used consistently. This example assumes that you are using Helm version 3.2.0 or later.

{{< clipboard >}}
<div class="highlight">

```
$ helm upgrade --install fluent-operator ocne-app-catalog/fluent-operator -n logging --create-namespace
```
</div>
{{< /clipboard >}}

Optionally, provide overrides when installing.

### Helm override recipes

The following recipes give examples of changing the configuration using Helm overrides.

#### Install from a private registry
To install using a private registry (for example, in a disconnected environment), you must override Helm values to change the image registry settings for all images.

**fo_privreg_overrides.yaml**
{{< clipboard >}}
<div class="highlight">

```
operator:
  initcontainer:
    repository: "my.registry.io/<image>"
    tag: "<image-tag>"
  container:
    repository: "my.registry.io/fluent-operator"
    tag: <image-tag>
fluentbit:
  image:
    repository: "my.registry.io/fluent-bit"
    tag: "<image-tag>"
```
</div>
{{< /clipboard >}}

**Note**: Verrazzano uses `ghcr.io/oracle/oraclelinux:8` as the `initcontainer` image for the operator. You can use any image in your registry that has Docker installed.

#### Configure inputs and buffer
By default, the tail input reads content from the tail of a file. We recommend overriding the tail input to read from the head of the file.

By default, the systemd journal logs directory is set to `/var/run/journal`. However, depending on the environment, the directory location may vary. For example, if the directory is `/run/log/journal`, add `additionalVolumes` and `additionalVolumeMounts` overrides for `fluentbit`, and override the path of systemd input to `/run/log/journal`.

By default, Fluent Bit uses an in-memory buffer, which may not be optimal for production environments. Optionally, configure the file system buffer for the inputs.

An example of the overrides covering these points.

**fo_fluentbit_input_buffer_override.yaml**
{{< clipboard >}}
<div class="highlight">

```
fluentbit:
  additionalVolumes:
    - hostPath:
        path: /run/log/journal
        type: ""
      name: run-log-journal
  additionalVolumesMounts:
    - mountPath: /run/log/journal
      name: run-log-journal
      readOnly: true   
  input:
    tail:
      readFromHead: true
      storageType: filesystem
      pauseOnChunksOverlimit: "on"
    systemd:
      path: "/run/log/journal"
      stripUnderscores: "on"
      systemdFilter:
        enable: false
      storageType: filesystem
      pauseOnChunksOverlimit: "on"
  service:
    storage:
      path: "/fluent-bit/tail/"
      backlogMemLimit: "5M"
      checksum: "off"
      metrics: "off"
      sync: normal
```
</div>
{{< /clipboard >}}

#### Configure pod and container security
Override pod and container security default settings to limit actions that pods and containers can perform in the cluster. These settings allow pods and containers to perform only operations that are needed for them to operate successfully, and to mitigate security vulnerabilities, such as privilege escalation.

The default user for Fluent Bit is root, which it needs to be able to read and write to `hostpath`. The following are the recommended security settings for Fluent Bit and Fluent Operator.

**fo_seccontext.yaml**
{{< clipboard >}}
<div class="highlight">

```
fluentbit:  
  # Pod security context for Fluentbit Pod. Ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
  podSecurityContext:
    seccompProfile:
      type: RuntimeDefault
  securityContext:
    allowPrivilegeEscalation: false
    privileged: false
    capabilities:
      drop:
      - ALL

operator:
  # Pod security context for Fluent Operator pod. Ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
  podSecurityContext:
    runAsGroup: 1025
    runAsNonRoot: true
    runAsUser: 1025
    seccompProfile:
      type: RuntimeDefault
  securityContext:
    allowPrivilegeEscalation: false
    privileged: false
    capabilities:
      drop:
        - ALL
```
</div>
{{< /clipboard >}}

#### Configuration to allow Prometheus to scrape metrics

The following override recipe will allow Fluent Bit to enable metrics and expose metrics data.

**fo_metrics.yaml**
{{< clipboard >}}
<div class="highlight">

```
fluentbit:
  input:
    fluentBitMetrics:
      scrapeInterval: "2"
      scrapeOnStart: true
      tag: "fb.metrics"  
  output:
    prometheusMetricsExporter:
      match: "fb.metrics"
      metricsExporter:
        host: "0.0.0.0"
        port: 2020
        addLabels:
          app: "fluentbit"
```

</div>
{{< /clipboard >}}

#### Configure the namespace ConfigSelector
The Fluent Operator supports configurability at the namespace level that lets you create Fluent Bit configurations for logs from your application namespace. Add a Helm override to add a label selector that allows FluentBit to select and map namespaced resources to a FluentBit instance. For example:

**fo_ns_cfg.yaml**
{{< clipboard >}}
<div class="highlight">

```
fluentbit:  
  namespaceFluentBitCfgSelector:
    matchLabels:
      my.label.selector/namespaceconfig: "mylabel"
```
</div>
{{< /clipboard >}}
