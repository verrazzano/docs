---
title: "Istio"
weight: 1
draft: false
---
This document shows you how to integrate Istio with other OCNE components.

## Fluent Bit
Follow the example, [Configure the namespace ConfigSelector]({{< relref "docs/guides/migrate/install/fluent/_index.md#configure-the-namespace-configselector" >}}), to add a Helm override for the namespace config label selector.

Then, apply the following manifest file in your cluster. Replace `<namespace-name>` with the namespace in which Istio is installed and `metadata.labels` of the FluentBitConfig custom resource with the Helm override that was supplied in the previous step.

**Note**: The following manifest file assumes that the namespace config label selector override was `my.label.selector/namespace-config: "mylabel"`.

**fo_ns_cfg.yaml**
{{< clipboard >}}
<div class="highlight">

```
apiVersion: fluentbit.fluent.io/v1alpha2
kind: FluentBitConfig
metadata:
  labels:
    my.label.selector/namespace-config: "mylabel"
  name: istio-fbc
  namespace: <namespace_name>
spec:
  filterSelector:
    matchLabels:
      fluentbit.fluent.io/component: "istio"
  parserSelector:
    matchLabels:
      fluentbit.fluent.io/component: "istio"
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Filter
metadata:
  labels:
    fluentbit.fluent.io/component: "istio"
  name: istio-filter
  namespace: <namespace_name>
spec:
  filters:
    - parser:
        keyName: log
        reserveData: true
        preserveKey: true
        parser: istio-parser
  match: "kube.*istiod*istio-system*discovery*"
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Parser
metadata:
  labels:
    fluentbit.fluent.io/component: "istio"
  name: istio-parser
  namespace: <namespace_name>
spec:
  regex:
    regex: '/^(?<logtime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{1,9}Z)\t(?<level>.*?)\t(?<message>[\s\S]*?)$/'
    timeKey: logtime
    timeKeep: true
    timeFormat: "%Y-%m-%dT%H:%M:%S.%LZ"
```

</div>
{{< /clipboard >}}

## Network policies
NetworkPolicies let you specify how a pod can communicate with various network entities in a cluster. NetworkPolicies increase the security posture of the cluster by limiting network traffic and preventing unwanted network communication. NetworkPolicy resources affect layer 4 connections (TCP, UDP, and optionally SCTP). The cluster must be running a Container Network Interface (CNI) plug-in that enforces NetworkPolicies.

Use the following commands to create NetworkPolicies in the `istio-system` namespace of your OCNE cluster, mimicking the NetworkPolicies that Verrazzano creates for Istio.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -n istio-system -f - <<EOF
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
$ kubectl apply -n istio-system -f - <<EOF
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
$ kubectl apply -n istio-system -f - <<EOF
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
$ kubectl apply -n istio-system -f - <<EOF
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
          - system-es-master
          - system-es-ingest
          - system-es-data
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
          app.kubernetes.io/name: ingress-nginx
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: grafana
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

Prometheus can scrape metrics from Istio Pilot and Envoy sidecars in the cluster. Apply the following Prometheus ServiceMonitor and PodMonitor resources to collect Istio metrics in all namespaces.
This example assumes that Istio has been installed in the `istio-system` namespace and Prometheus has been installed in the `monitoring` namespace.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  labels:
    release: prometheus-operator
  name: pilot
  namespace: monitoring
spec:
  endpoints:
  - enableHttp2: false
    relabelings:
    - action: keep
      regex: istiod;http-monitoring
      sourceLabels:
      - __meta_kubernetes_service_name
      - __meta_kubernetes_endpoint_port_name
    - action: replace
      sourceLabels:
      - __meta_kubernetes_service_label_app
      targetLabel: app
  namespaceSelector:
    matchNames:
    - istio-system
  selector: {}
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  labels:
    release: prometheus-operator
  name: envoy-stats
  namespace: monitoring
spec:
  namespaceSelector:
    any: true
  podMetricsEndpoints:
  - enableHttp2: false
    path: /stats/prometheus
    relabelings:
    - action: keep
      regex: .*-envoy-prom
      sourceLabels:
      - __meta_kubernetes_pod_container_port_name
    - action: drop
      regex: Succeeded
      sourceLabels:
      - __meta_kubernetes_pod_phase
    - action: replace
      regex: ([^:]+)(?::\d+)?;(\d+)
      replacement: $1:15090
      sourceLabels:
      - __address__
      - __meta_kubernetes_pod_annotation_prometheus_io_port
      targetLabel: __address__
    - action: labeldrop
      regex: __meta_kubernetes_pod_label_(.+)
    - action: replace
      sourceLabels:
      - __meta_kubernetes_namespace
      targetLabel: namespace
    - action: replace
      sourceLabels:
      - __meta_kubernetes_pod_name
      targetLabel: pod_name
  selector: {}
```
</div>
{{< /clipboard >}}
