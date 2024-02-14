---
title: "OpenSearch"
weight: 1
draft: false
---
This document shows you how to integrate OpenSearch with other OCNE components.

## Network Policies
## Ingress
## Istio
## Prometheus

Apply the following `ServiceMonitor` resource to scrape metrics from OpenSearch pods. This assumes Prometheus Operator has been installed in the `monitoring` namespace and OpenSearch has been installed in the `logging` namespace.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  labels:
    release: prometheus-operator
  name: opensearch
  namespace: monitoring
spec:
  endpoints:
  - enableHttp2: false
    path: /_prometheus/metrics
    relabelings:
    - action: keep
      regex: opensearch-cluster-.*
      sourceLabels:
      - __meta_kubernetes_pod_name
    - action: keep
      regex: "9200"
      sourceLabels:
      - __meta_kubernetes_pod_container_port_number
    - action: replace
      sourceLabels:
      - __meta_kubernetes_namespace
      targetLabel: namespace
    - action: replace
      sourceLabels:
      - __meta_kubernetes_pod_name
      targetLabel: kubernetes_pod_name
    scheme: https
    tlsConfig:
      caFile: /etc/istio-certs/root-cert.pem
      certFile: /etc/istio-certs/cert-chain.pem
      insecureSkipVerify: true
      keyFile: /etc/istio-certs/key.pem
  namespaceSelector:
    matchNames:
    - logging
  selector: {}
```
</div>
{{< /clipboard >}}

This `ServiceMonitor` assumes OpenSearch is running in the Istio mesh. If OpenSearch is not in the Istio mesh, then remove the `tlsConfig` and change the `scheme` to `http`.
