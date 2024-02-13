---
title: "Istio"
weight: 1
draft: false
---
This document shows you how to integrate Istio with other OCNE components.

## Fluent Bit
## Network Policies
NetworkPolicies allow you to specify how a pod is allowed to communicate with various network entities in a cluster. NetworkPolicies increase the security posture of the cluster by limiting network traffic and preventing unwanted network communication. NetworkPolicy resources affect layer 4 connections (TCP, UDP, and optionally SCTP). The cluster must be running a Container Network Interface (CNI) plug-in that enforces NetworkPolicies.

Use the following commands to create NetworkPolicies in the `istio-system` namespace of your OCNE cluster, mimicking the NetworkPolicies that Verrazzano creates for Istio.

{{< clipboard >}}
<div class="highlight">

```
kubectl apply -n istio-system -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-same-namespace
  namespace: istio-system
spec:
  ingress:
  - from:
    - podSelector: {}
  podSelector: {}
  policyTypes:
  - Ingress
EOF
```
</div>
{{< /clipboard >}}

{{< clipboard >}}
<div class="highlight">

```
kubectl apply -n istio-system -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: istio-egressgateway
  namespace: istio-system
spec:
  ingress:
  - ports:
    - port: 8443
      protocol: TCP
  - from:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
    ports:
    - port: 15090
      protocol: TCP
  podSelector:
    matchLabels:
      app: istio-egressgateway
  policyTypes:
  - Ingress
EOF
```
</div>
{{< /clipboard >}}


{{< clipboard >}}
<div class="highlight">

```
kubectl apply -n istio-system -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: istio-ingressgateway
  namespace: istio-system
spec:
  ingress:
  - ports:
    - port: 8443
      protocol: TCP
  - from:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
    ports:
    - port: 15090
      protocol: TCP
  podSelector:
    matchLabels:
      app: istio-ingressgateway
  policyTypes:
  - Ingress
EOF
```
</div>
{{< /clipboard >}}

{{< clipboard >}}
<div class="highlight">

```
kubectl apply -n istio-system -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: istiod-access
  namespace: istio-system
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          istio-injection: enabled
    ports:
    - port: 15012
      protocol: TCP
  - from:
    - namespaceSelector:
        matchLabels:
          istio-injection: enabled
    - podSelector:
        matchExpressions:
        - key: app
          operator: In
          values:
          - fluentd
          - system-es-master
          - system-es-ingest
          - system-es-data
          - system-grafana
          - system-osd
          - weblogic-operator
    - podSelector:
        matchExpressions:
        - key: app.kubernetes.io/name
          operator: In
          values:
          - fluent-operator
          - fluent-bit
    - podSelector:
        matchLabels:
          job-name: load-dump
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: ingress-nginx
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
    - podSelector:
        matchLabels:
          app: jaeger
    - podSelector:
        matchExpressions:
        - key: app.kubernetes.io/component
          operator: In
          values:
          - query
          - query-frontend
          - storegateway
    - podSelector:
        matchLabels:
          app.kubernetes.io/instance: argocd
    - podSelector:
        matchLabels:
          app.kubernetes.io/instance: velero
          app.kubernetes.io/name: velero
    ports:
    - port: 15012
      protocol: TCP
  - ports:
    - port: 15017
      protocol: TCP
  - from:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
    ports:
    - port: 15014
      protocol: TCP
  podSelector:
    matchLabels:
      app: istiod
  policyTypes:
  - Ingress
EOF
```
</div>
{{< /clipboard >}}

## Prometheus
