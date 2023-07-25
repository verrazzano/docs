---
title: "Gather Metrics and Collect Logs"
weight: 2
draft: false
---

Use Prometheus to collect system performance metrics and metrics for applications deployed or managed by Verrazzano. For information, see [Prometheus]({{< relref "/docs/observability/monitoring/configure/prometheus.md" >}}).

### Gather metrics
The following is an example of using Prometheus to scrape the metrics endpoint of the Hello Helidon Greet application.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  labels:
    release: prometheus-operator
  name: hello-helidon
  namespace: hello-helidon
spec:
  endpoints:
  - bearerTokenSecret:
      key: ""
    enableHttp2: false
    path: /metrics
    relabelings:
    - action: replace
      replacement: local
      targetLabel: verrazzano_cluster
    - action: keep
      regex: true;hello-helidon
      sourceLabels:
      - __meta_kubernetes_pod_annotation_verrazzano_io_metricsEnabled
      - __meta_kubernetes_pod_label_app
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
</div>
{{< /clipboard >}}

### Wiring for logs
Application logs record events happening in the Kubernetes cluster, which are automatically accessed by Verrazzano when required.  
