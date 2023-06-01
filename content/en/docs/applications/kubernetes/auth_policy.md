---
title: "Authorization Policy"
description: "Learn about authorization policies"
weight: 4
draft: false
---

An authorization policy enables access control on workloads in the mesh.
Also, an authorization policy supports both allow and deny policies. In the following example, the authorization policy allows access from the listed service accounts that can access the Hello Helidon Greet application.

{{< clipboard >}}
<div class="highlight">

```
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  labels:
    verrazzano.io/istio: hello-helidon
  name: hello-helidon
  namespace: hello-helidon
spec:
  rules:
  - from:
    - source:
        principals:
        - cluster.local/ns/hello-helidon/sa/hello-helidon
        - cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account
        - cluster.local/ns/verrazzano-system/sa/verrazzano-monitoring-operator
        - cluster.local/ns/verrazzano-monitoring/sa/prometheus-operator-kube-p-prometheus
  selector:
    matchLabels:
      verrazzano.io/istio: hello-helidon
```
</div>
{{< /clipboard >}}
