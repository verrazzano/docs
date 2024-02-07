---
title: "WebLogic Kubernetes Operator"
weight: 1
draft: false
---
This document shows you how to integrate WebLogic Kubernetes Operator with other OCNE components.

## Fluent Bit

## Network Policies
The following Network Policy must be created in the `weblogic-operator` namespace. This Network Policy for a WebLogic Kubernetes Operator pod allows the following:

- Allows ingress traffic to any port from the `istio-system` namespace
- Allows ingress traffic to envoy port 15090 from the Prometheus pod in the `verrazzano-monitoring` namespace
- Egress traffic is not restricted

{{< clipboard >}}
<div class="highlight">

```
kubectl apply -n weblogic-operator -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: weblogic-operator
  namespace: weblogic-operator
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: istio-system
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
      podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
    ports:
    - port: 15090
      protocol: TCP
  podSelector:
    matchLabels:
       app: weblogic-operator
  policyTypes:
  - Ingress
EOF
```
</div>
{{< /clipboard >}}

## Prometheus
