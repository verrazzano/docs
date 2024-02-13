---
title: "Istio"
weight: 1
draft: false
---
This document shows you how to integrate Istio with other OCNE components.

## Fluent Bit
## Network Policies
## Prometheus

Prometheus can scrape metrics from Istio Pilot and Envoy sidecars in the cluster. Apply the following Prometheus ServiceMonitor and PodMonitor resources to collect Istio metrics in all namespaces.
This example assumes that Istio has been installed in the `istio-system` namespace and Prometheus has been installed in the `monitoring` namespace.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  labels:
    release: prometheus-operator
  name: pilot
  namespace: monitoring
spec:
  endpoints:
  - enableHttp2: false
    relabelings:
    - action: keep
      regex: istiod;http-monitoring
      sourceLabels:
      - __meta_kubernetes_service_name
      - __meta_kubernetes_endpoint_port_name
    - action: replace
      sourceLabels:
      - __meta_kubernetes_service_label_app
      targetLabel: app
  namespaceSelector:
    matchNames:
    - istio-system
  selector: {}
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  labels:
    release: prometheus-operator
  name: envoy-stats
  namespace: monitoring
spec:
  namespaceSelector:
    any: true
  podMetricsEndpoints:
  - enableHttp2: false
    path: /stats/prometheus
    relabelings:
    - action: keep
      regex: .*-envoy-prom
      sourceLabels:
      - __meta_kubernetes_pod_container_port_name
    - action: drop
      regex: Succeeded
      sourceLabels:
      - __meta_kubernetes_pod_phase
    - action: replace
      regex: ([^:]+)(?::\d+)?;(\d+)
      replacement: $1:15090
      sourceLabels:
      - __address__
      - __meta_kubernetes_pod_annotation_prometheus_io_port
      targetLabel: __address__
    - action: labeldrop
      regex: __meta_kubernetes_pod_label_(.+)
    - action: replace
      sourceLabels:
      - __meta_kubernetes_namespace
      targetLabel: namespace
    - action: replace
      sourceLabels:
      - __meta_kubernetes_pod_name
      targetLabel: pod_name
  selector: {}
```
</div>
{{< /clipboard >}}
