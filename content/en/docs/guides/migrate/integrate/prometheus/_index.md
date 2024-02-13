---
title: "Prometheus"
weight: 1
draft: false
---
This document shows you how to integrate Prometheus with other OCNE components.

## Fluent Bit
## Ingress
## Istio

The Istio Authorization Policy custom resource enables access control on workloads in the mesh.

Apply the following custom resource to allow the authenticating proxy to forward network traffic to the Prometheus web UI. This example assumes the `kube-prometheus-stack` Helm release name is `prometheus-operator`.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: prometheus-authzpol
  namespace: monitoring
spec:
  rules:
  - from:
    - source:
        namespaces:
        - TBD FILL THIS IN WITH THE NAMESPACE OF THE AUTHENTICATING PROXY
        principals:
        - cluster.local/ns/TBD FILL THIS IN WITH THE SERVICE ACCOUNT OF THE AUTHENTICATING PROXY
    to:
    - operation:
        ports:
        - "9090"
  selector:
    matchLabels:
      app.kubernetes.io/name: prometheus
EOF
```
</div>
{{< /clipboard >}}

Prometheus can scrape metrics from Istio Envoy sidecars in the cluster. Apply the following Prometheus PodMonitor resource to collect Envoy metrics in all namespaces.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
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

## Network policies
NetworkPolicies let you specify how a pod is allowed to communicate with various network entities in a cluster. NetworkPolicies increase the security posture of the cluster by limiting network traffic and preventing unwanted network communication. NetworkPolicy resources affect layer 4 connections (TCP, UDP, and optionally SCTP). The cluster must be running a Container Network Interface (CNI) plug-in that enforces NetworkPolicies.

As an example, run the following command to apply NetworkPolicy resources to only allow Prometheus to access the metrics ports on monitoring component pods. Note that these policies only affect ingress. Egress from the monitoring namespace is not impacted.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: node-exporter
  namespace: monitoring
spec:
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
    ports:
    - port: 9100
      protocol: TCP
  podSelector:
    matchLabels:
      app.kubernetes.io/name: prometheus-node-exporter
  policyTypes:
  - Ingress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kube-state-metrics
  namespace: monitoring
spec:
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
    ports:
    - port: 8080
      protocol: TCP
  podSelector:
    matchLabels:
      app.kubernetes.io/name: kube-state-metrics
  policyTypes:
  - Ingress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kube-prometheus-stack-operator
  namespace: monitoring
spec:
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
    ports:
    - port: 443
      protocol: TCP
  podSelector:
    matchLabels:
      app: kube-prometheus-stack-operator
  policyTypes:
  - Ingress
EOF
```
</div>
{{< /clipboard >}}

**TBD** Add NetworkPolicies when we figure out how auth and ingress are going to work. This will impact Grafana, Alertmanager, and Prometheus as they all have web UIs.

