---
title: "Prometheus"
weight: 1
draft: false
---
This document shows you how to integrate Prometheus with other OCNE components.

## Fluent Bit
First, follow the example, [Configure the namespace ConfigSelector]({{< relref "docs/guides/migrate/install/fluent/_index.md#configure-the-namespace-configselector" >}}), to add a Helm override for the namespace config label selector.

Then, apply the following manifest file in your cluster. Replace `<namespace-name>` with the namespace in which Prometheus is installed and `metadata.labels` of the FluentBitConfig custom resource with the Helm override that was supplied in the previous step.

**Note**: The following manifest file assumes that the namespace config label selector override was `my.label.selector/namespace-config: "mylabel"`.

**fo_prom.yaml**
{{< clipboard >}}
<div class="highlight">

```
apiVersion: fluentbit.fluent.io/v1alpha2
kind: FluentBitConfig
metadata:
  labels:
    my.label.selector/namespace-config: "mylabel"
  name: prometheus-fbc
  namespace: {{ template "kube-prometheus-stack.namespace" . }}
spec:
  filterSelector:
    matchLabels:
      fluentbit.fluent.io/component: "prometheus"
  parserSelector:
    matchLabels:
      fluentbit.fluent.io/component: "prometheus"
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Filter
metadata:
  labels:
    fluentbit.fluent.io/component: "prometheus"
  name: prometheus-filter
  namespace: <namespace_name>
spec:
  filters:
    - parser:
        keyName: log
        reserveData: true
        preserveKey: true
        parser: prometheus-parser1,prometheus-parser2,prometheus-parser3,prometheus-parser4,prometheusconfig-parser
  match: "kube.*prometheus-operator*"
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Parser
metadata:
  labels:
    fluentbit.fluent.io/component: "prometheus"
  name: prometheusconfig-parser
  namespace: <namespace_name>
spec:
  regex:
    regex: '/^(?<logtime>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) (?<message>[\s\S]*?)$/'
    timeKey: logtime
    timeKeep: true
    timeFormat: "%Y/%m/%d %H:%M:%S"
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Parser
metadata:
  labels:
    fluentbit.fluent.io/component: "prometheus"
  name: prometheus-parser1
  namespace: <namespace_name>
spec:
  regex:
    regex: '/^ts=(?<logtime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z)(.*)level=(?<level>.*?) (.*?)msg="(?<message>.*?)"([\s\S]*?)$/'
    timeKey: logtime
    timeKeep: true
    timeFormat: "%Y-%m-%dT%H:%M:%S.%LZ"
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Parser
metadata:
  labels:
    fluentbit.fluent.io/component: "prometheus"
  name: prometheus-parser2
  namespace: <namespace_name>
spec:
  regex:
    regex: '/^ts=(?<logtime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z)(.*)level=(?<level>.*?) (?<message>[\s\S]*?)$/'
    timeKey: logtime
    timeKeep: true
    timeFormat: "%Y-%m-%dT%H:%M:%S.%LZ"
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Parser
metadata:
  labels:
    fluentbit.fluent.io/component: "prometheus"
  name: prometheus-parser3
  namespace: <namespace_name>
spec:
  regex:
    regex: '/^(?<level>.)(\d{2}\d{2}) (?<logtime>\d{2}:\d{2}:\d{2}.\d{6})\s*?(?<message>[\s\S]*?)$/'
    timeKey: logtime
    timeKeep: true
    timeFormat: "%H:%M:%S.%L"
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Parser
metadata:
  labels:
    fluentbit.fluent.io/component: "prometheus"
  name: prometheus-parser4
  namespace: <namespace_name>
spec:
  regex:
    regex: '/^level=(?<level>.*?) ts=(?<logtime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{1,9}Z)(?:.*msg="(?<message>[^"]+)")?[\s\S]*?$/'
    timeKey: logtime
    timeKeep: true
    timeFormat: "%Y-%m-%dT%H:%M:%S.%LZ"
```

</div>
{{< /clipboard >}}

## Ingress
An ingress exposes HTTP and HTTPS routes from outside the cluster to services within the cluster. Traffic routing is controlled by the rules defined on the Ingress resource. For more information, see [Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/).

#### Create an Ingress to forward requests to Prometheus
The following example creates an ingress to forward requests to the Prometheus back end, using cert-manager ingress annotations to create a TLS certificate for the endpoint signed by `my-cluster-issuer` ClusterIssuer.

This example assumes:
- cert-manager is installed and a ClusterIssuer `my-cluster-issuer` is created.
- The `kube-prometheus-stack` is installed in the `monitoring` namespace with a Prometheus instance created `prometheus-operator-kube-p-prometheus` with a clusterIP service.
- The Prometheus instance is listening on the default port `9090`.
- An ingress controller is installed in the `ingress-nginx` namespace, with an external IP address, `10.0.0.1`.

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

As an example, run the following command to apply NetworkPolicy resources to allow only Prometheus to access the metrics ports on the monitoring component pods. Note that these policies only affect ingress. Egress from the `monitoring` namespace is not impacted.

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
