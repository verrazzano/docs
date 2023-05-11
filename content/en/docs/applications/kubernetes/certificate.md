---
title: "Certificate Management"
description: "Learn about certificate management"
weight: 3
draft: false
---

The following is an example to secure public access to the Hello Helidon Greet application.

Replace _domain name_ with the Kubernetes cluster domain used in Verrazzano. This ensures that you have a fully-qualified domain name for host entries in the resources.

{{< clipboard >}}
<div class="highlight">

```
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: hello-helidon-hello-helidon-ingress-cert
  namespace: istio-system # Note the use of the istio-system Namespace.
spec:
  dnsNames:
  - hello-helidon.hello-helidon.<domain name>
  issuerRef:
    kind: ClusterIssuer
    name: verrazzano-cluster-issuer
  secretName: hello-helidon-hello-helidon-ingress-cert-secret
```
</div>
{{< /clipboard >}}
