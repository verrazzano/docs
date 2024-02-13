---
title: "Istio"
weight: 1
draft: false
---
This document shows you how to integrate Istio with other OCNE components.

## Fluent Bit
## Network Policies
NetworkPolicies allow you to specify how a pod is allowed to communicate with various network entities in a cluster. NetworkPolicies increase the security posture of the cluster by limiting network traffic and preventing unwanted network communication. NetworkPolicy resources affect layer 4 connections (TCP, UDP, and optionally SCTP). The cluster must be running a Container Network Interface (CNI) plug-in that enforces NetworkPolicies.

The following network policies must be created in the `istio-system` namespace of your OCNE cluster.

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
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-monitoring # FIXME
      podSelector:
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
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-monitoring # FIXME
      podSelector:
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
  name: istiocoredns
  namespace: istio-system
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: kube-system # FIXME
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
  podSelector:
    matchLabels:
      app: istiocoredns
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
          verrazzano-managed: "true" # FIXME
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-system # FIXME
      podSelector:
        matchLabels:
          k8s-app: verrazzano-monitoring-operator # FIXME
    ports:
    - port: 15012
      protocol: TCP
  - from:
    - namespaceSelector:
        matchLabels:
          istio-injection: enabled
          verrazzano-managed: "true" # FIXME
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-system # FIXME
      podSelector:
        matchExpressions:
        - key: app
          operator: In
          values:
          - fluentd
          - verrazzano-authproxy # FIXME
          - verrazzano-console # FIXME
          - system-es-master
          - system-es-ingest
          - system-es-data
          - system-grafana
          - system-osd
          - weblogic-operator
          - kiali
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-system # FIXME
      podSelector:
        matchExpressions:
        - key: app.kubernetes.io/name
          operator: In
          values:
          - fluent-operator
          - fluent-bit
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: keycloak # FIXME
      podSelector:
        matchLabels:
          app.kubernetes.io/name: keycloak
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: keycloak # FIXME
      podSelector:
        matchLabels:
          tier: mysql
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: keycloak # FIXME
      podSelector:
        matchLabels:
          job-name: load-dump
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: mysql-operator # FIXME
      podSelector:
        matchLabels:
          name: mysql-operator
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-ingress-nginx # FIXME
      podSelector:
        matchLabels:
          app.kubernetes.io/name: ingress-nginx
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-monitoring # FIXME
      podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-monitoring # FIXME
      podSelector:
        matchLabels:
          app: jaeger
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-monitoring # FIXME
      podSelector:
        matchExpressions:
        - key: app.kubernetes.io/component
          operator: In
          values:
          - query
          - query-frontend
          - storegateway
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: mysql-operator # FIXME
      podSelector:
        matchLabels:
          name: mysql-operator
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: argocd # FIXME
      podSelector:
        matchLabels:
          app.kubernetes.io/instance: argocd
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-backup # FIXME
      podSelector:
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
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-monitoring # FIXME
      podSelector:
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
