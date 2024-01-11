---
title: "MetricsTrait"
linkTitle: "MetricsTrait"
description: "Review the Kubernetes objects Verrazzano creates for an OAM MetricsTrait"
weight: 5
draft: false
---

Verrazzano generates the following Kubernetes objects for a [MetricsTrait]({{< relref "/docs/applications/oam/traits/metrics/metrics.md" >}}):
* monitoring.coreos.com/v1/ServiceMonitor - A Prometheus custom object that defines a service from which to scrape metrics.  A ServiceMonitor object is created by default unless explicitly disabled in the MetricsTrait.
* Annotations on objects to be scraped by Prometheus (for example, pods). The annotation names are prefixed with `verrazzano.io/metrics`.

For example, the following MetricsTrait is defined for the component, `hello-helidon-component`, of the [Hello World Helidon]({{< relref "/docs/examples/hello-helidon/_index.md" >}}) example.
```
apiVersion: oam.verrazzano.io/v1alpha1
kind: MetricsTrait
spec:
    scraper: verrazzano-system/vmi-system-prometheus-0
```

A ServiceMonitor object, similar to the following one, will be created. The `path` defaults to `metrics`.
```
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  labels:
    release: prometheus-operator
  name: hello-helidon-hello-helidon-hello-helidon-component
  namespace: hello-helidon
spec:
  endpoints:
  - bearerTokenSecret:
      key: ""
    enableHttp2: false
    path: metrics
    relabelings:
    - action: replace
      replacement: local
      targetLabel: verrazzano_cluster
    - action: keep
      regex: true;hello-helidon;hello-helidon-component
      sourceLabels:
      - __meta_kubernetes_pod_annotation_verrazzano_io_metricsEnabled
      - __meta_kubernetes_pod_label_app_oam_dev_name
      - __meta_kubernetes_pod_label_app_oam_dev_component
    - action: replace
      regex: (.+)
      sourceLabels:
      - __meta_kubernetes_pod_annotation_verrazzano_io_metricsPath
      targetLabel: __metrics_path__
    - action: replace
      regex: ([^:]+)(?::\d+)?;(\d+)
      replacement: $1:$2
      sourceLabels:
      - __address__
      - __meta_kubernetes_pod_annotation_verrazzano_io_metricsPort
      targetLabel: __address__
    - action: replace
      regex: (.*)
      replacement: $1
      sourceLabels:
      - __meta_kubernetes_namespace
      targetLabel: namespace
    - action: labelmap
      regex: __meta_kubernetes_pod_label_(.+)
    - action: replace
      sourceLabels:
      - __meta_kubernetes_pod_name
      targetLabel: pod_name
    - action: labeldrop
      regex: (controller_revision_hash)
    - action: replace
      regex: .*/(.*)$
      replacement: $1
      sourceLabels:
      - name
      targetLabel: webapp
    - action: replace
      regex: ;(.*)
      replacement: $1
      separator: ;
      sourceLabels:
      - application
      - app
      targetLabel: application
    scheme: https
    tlsConfig:
      ca: {}
      caFile: /etc/istio-certs/root-cert.pem
      cert: {}
      certFile: /etc/istio-certs/cert-chain.pem
      insecureSkipVerify: true
      keyFile: /etc/istio-certs/key.pem
  namespaceSelector:
    matchNames:
    - hello-helidon
  selector: {}
```

The following is a snippet of the Deployment object that will be annotated based on the MetricsTrait definition.  The `port` defaults to `8080`.
```
apiVersion: apps/v1
kind: Deployment
.
.
spec:
  template:
    metadata:
      annotations:
        verrazzano.io/metricsEnabled: "true"
        verrazzano.io/metricsPath: metrics
        verrazzano.io/metricsPort: "8080"
```
