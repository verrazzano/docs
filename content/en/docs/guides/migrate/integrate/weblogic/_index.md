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

## Migrate OAM WebLogic applications to OCNE 2.0
As part of the migration, each OAM WebLogic application needs to be moved from the Verrazzano environment to the OCNE 2.0 environment. You will need to redeploy each OAM application in OCNE 2.0 without using OAM. This process is described in [OAM to Kubernetes Mappings]({{< relref "/docs/guides/migrate/oam-to-kubernetes/_index.md" >}}).

For each OAM application, start with the following command in your Verrazzano environment.

{{< clipboard >}}
<div class="highlight">

```
$ vz export oam --name <app-name> --namespace <app-namespace> > myapp.yaml
```
</div>
{{< /clipboard >}}

This generates a YAML file for the OAM application in `myapp.yaml`. Make any local customizations to the generated YAML file, and then apply the YAML file to the OCNE 2.0 environment by continuing to follow the documentation.
