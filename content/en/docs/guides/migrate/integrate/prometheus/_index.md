---
title: "Prometheus"
weight: 1
draft: false
---
This document shows you how to integrate Prometheus with other OCNE components.

## Fluent Bit
Follow example provided in [fluent operator helm override recipe for namespace configurations]({{< relref "docs/guides/migrate/install/fluent/_index.md#namespace-configselector" >}}) to add a helm override for namespace config label selector.

Then, apply the following manifest in your cluster. Replace <namespace-name> with the namespace in which prometheus is installed and `metadata.labels` of FluentBitConfig custom resource with the helm override that was supplied in the previous step.

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

## Ingress
Ingress exposes HTTP and HTTPS routes from outside the cluster to services within the cluster. Traffic routing is controlled by the rules defined on the Ingress resource. Please refer to [Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/) for more details.

#### Create an Ingress to forward requests to Prometheus
The following example creates an Ingress to forward requests to the Prometheus backend, using cert-manager ingress annotations to create a TLS certificate for the endpoint signed by `my-cluster-issuer` ClusterIssuer.

The instructions assume:
1. Cert Manager is installed and a ClusterIssuer `my-cluster-issuer` is created
2. The `kube-prometheus-stack` is installed in `monitoring` namespace with Prometheus instance created be `prometheus-operator-kube-p-prometheus` with a clusterIP service
3. The Prometheus instance is listening on default port `9090`
4. Ingress Controller is installed in `ingress-nginx` namespace, with external IP `10.0.0.1`

   {{<clipboard >}}
   <div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    cert-manager.io/cluster-issuer: my-cluster-issuer
    cert-manager.io/common-name: prometheus.10.0.0.1.nip.io
  name: prometheus
  namespace: monitoring
spec:
  ingressClassName: nginx
  rules:
  - host: prometheus.10.0.0.1.nip.io
    http:
      paths:
      - backend:
          service:
            name: prometheus-operator-kube-p-prometheus
            port:
              number: 9090
        path: /
        pathType: Prefix
  tls:
  - hosts:
    - prometheus.10.0.0.1.nip.io
    secretName: kube-prometheus-stack-prometheus-tls
EOF
```

   </div>
   {{< /clipboard >}}

The ingress in this case utilizes the wildcard DNS service [nip.io](https://nip.io/) to create an address, that will forward requests to the Prometheus ClusterIP service.

## Istio

The Istio Authorization Policy custom resource enables access control on workloads in the mesh.

Apply the following custom resource to allow the authenticating proxy to forward network traffic to the Prometheus web UI. This example assumes Prometheus is installed in the `monitoring` namespace.
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

