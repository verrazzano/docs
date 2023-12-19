---
title: "MetricsTrait"
linkTitle: "MetricsTrait"
description: "An overview of the Kubernetes resources Verrazzano creates for an OAM MetricsTrait"
weight: 5
draft: false
---

## MetricsTrait (oam.verrazzano.io/v1alpha1)

Verrazzano will generate the following Kubernetes resources for a MetricsTrait:
* ServiceMonitor - defines the monitoring of the application by Prometheus.  Created by default unless explicitly disabled in MetricsTrait.
* Annotations on deployment

For example, the following MetricsTrait definition will result in the Gateway, VirtualService and Secret objects shown below.
```
apiVersion: oam.verrazzano.io/v1alpha1
kind: MetricsTrait
spec:
    scraper: verrazzano-system/vmi-system-prometheus-0
```




Example of generated ServiceMonitor:
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
    path: metrics2
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


```
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
    deployment.kubernetes.io/revision: "5"
    description: Hello Helidon application
    version: v1.0.0
  labels:
    app: hello-helidon
    app.oam.dev/component: hello-helidon-component
    app.oam.dev/name: hello-helidon
    app.oam.dev/resourceType: WORKLOAD
    app.oam.dev/revision: ""
    version: v1
  name: hello-helidon-deployment
  namespace: hello-helidon
spec:
  progressDeadlineSeconds: 600
  replicas: 1
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      verrazzanohelidonworkloads.oam.verrazzano.io: a83aebe2-7a7b-44ca-abfc-ac6951a30629
  strategy:
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25%
    type: RollingUpdate
  template:
    metadata:
      annotations:
        verrazzano.io/metricsEnabled: "true"
        verrazzano.io/metricsPath: metrics2
        verrazzano.io/metricsPort: "8081"
```
