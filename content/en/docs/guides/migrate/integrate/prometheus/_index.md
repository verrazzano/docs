---
title: "Prometheus"
weight: 1
draft: false
---
This document shows you how to integrate Prometheus with other OCNE components.

## Fluent Bit
## Ingress
## Istio
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

