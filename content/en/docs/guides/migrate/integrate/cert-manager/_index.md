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

## Fluent Bit
Follow example provided in [fluent operator helm override recipe for namespace configurations]({{< relref "docs/guides/migrate/install/fluent/_index.md#namespace-configselector" >}}) to add a helm override for namespace config label selector.

Then, apply the following manifest in your cluster. Replace <namespace-name> with the namespace in which cert-manager is installed and `metadata.labels` of FluentBitConfig custom resource with the helm override that was supplied in the previous step.

**Note**: The manifest below assumes that the namespace config label selector override was `my.label.selector/namespace-config: "mylabel"` following the fluent operator helm override recipe.

**fo_ns_cfg.yaml**
{{< clipboard >}}
<div class="highlight">

```yaml
apiVersion: fluentbit.fluent.io/v1alpha2
kind: FluentBitConfig
metadata:
  labels:
    my.label.selector/namespace-config: "mylabel"
  name: certmanager-fbc
  namespace: <namespace_name>
spec:
  filterSelector:
    matchLabels:
      fluentbit.fluent.io/component: "certmanager"
  parserSelector:
    matchLabels:
      fluentbit.fluent.io/component: "certmanager"
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Filter
metadata:
  labels:
    fluentbit.fluent.io/component: "certmanager"
  name: certmanager-filter
  namespace: <namespace_name>
spec:
  filters:
    - parser:
        keyName: log
        reserveData: true
        preserveKey: true
        parser: certmanager-parser
  match: "kube.*cert-manager*cert-manager*"
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Parser
metadata:
  labels:
    fluentbit.fluent.io/component: "certmanager"
  name: certmanager-parser
  namespace: <namespace_name>
spec:
  regex:
    regex: '/^(?<level>.)(\d{2}\d{2}) (?<logtime>\d{2}:\d{2}:\d{2}.\d{6})\s*?(?<message>[\s\S]*?)$/'
    timeKey: logtime
    timeKeep: true
    timeFormat: "%H:%M:%S.%L"
```

</div>
{{< /clipboard >}}

## Network Policies
