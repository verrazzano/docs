---
title: "cert-manager"
weight: 1
draft: false
---
This document shows you how to integrate cert-manager with other OCNE components.
## Network Policies
NetworkPolicies allow you to specify how a pod is allowed to communicate with various network entities in a cluster. NetworkPolicies increase the security posture of the cluster by limiting network traffic and preventing unwanted network communication. NetworkPolicy resources affect layer 4 connections (TCP, UDP, and optionally SCTP). The cluster must be running a Container Network Interface (CNI) plug-in that enforces NetworkPolicies.

For example, if Prometheus is installed in the target cluster and you wish to limit access to cert-manager only from Prometheus for metrics scraping, you can apply a network policy to enforce this.

If the Prometheus instance is installed using the Prometheus operator in the namespace monitoring with the label `myapp.io/namespace=monitoring`, then the network policy can be applied as follows.
{{< clipboard >}}
<div class="highlight">

```
kubectl apply -n cert-manager -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cert-manager
  namespace: cert-manager
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          myapp.io/namespace: monitoring
      podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
    ports:
    - port: 9402
      protocol: TCP
  podSelector:
    matchLabels:
      app: cert-manager
  policyTypes:
  - Ingress
EOF
```
</div>
{{< /clipboard >}}

This will restrict ingress to be allowed only to pods in the `cert-manager` namespace with the `app: cert-manager` label on TCP port 9402 from Prometheus pods the `monitoring`  namespace.
