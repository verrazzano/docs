---
title: "MetricsTrait"
linkTitle: "MetricsTrait"
description: "An overview of the Kubernetes resources Verrazzano creates for an OAM MetricsTrait"
weight: 5
draft: false
---

## MetricsTrait (oam.verrazzano.io/v1alpha1)

Verrazzano will generate the following Kubernetes resources for a [MetricsTrait]({{< relref "/docs/reference/vao-oam-v1alpha1#oam.verrazzano.io/v1alpha1.MetricsTrait" >}}):
* monitoring.coreos.com/v1/ServiceMonitor - a Prometheus custom resource that defines an application to scrape metrics from.  A ServiceMonitor resource is created by default unless explicitly disabled in the MetricsTrait. 
* Annotations on resources to be scraped by Prometheus (e.g. pods). The annotation names are prefixed with `verrazzano.io/metrics`

For example, the MetricsTrait below is defined for the component `hello-helidon-component` of the hello-helidon sample.
```
apiVersion: oam.verrazzano.io/v1alpha1
kind: MetricsTrait
spec:
    scraper: verrazzano-system/vmi-system-prometheus-0
    port: 8080
    path: metrics
```

A ServiceMonitor resource similar to the one below will be created.
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

Below is a snippet of the Deployment resource that will be annotated based on the MetricsTrait definition.
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
