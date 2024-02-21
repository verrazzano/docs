---
title: "Ingress NGINX Controller"
weight: 1
draft: false
---
This document shows you how to integrate Ingress NGINX Controller with other OCNE components.

## Fluent Bit
Follow example provided in [fluent operator helm override recipe for namespace configurations]({{< relref "docs/guides/migrate/install/fluent/_index.md#namespace-configselector" >}}) to add a helm override for namespace config label selector.

Then, apply the following manifest in your cluster. Replace <namespace-name> with the namespace in which nginx is installed and `metadata.labels` of FluentBitConfig custom resource with the helm override that was supplied in the previous step.

**Note**: The manifest below assumes that the namespace config label selector override was `my.label.selector/namespace-config: "mylabel"` following the fluent operator helm override recipe.

**fo_nginx.yaml**
{{< clipboard >}}
<div class="highlight">

```yaml
apiVersion: fluentbit.fluent.io/v1alpha2
kind: FluentBitConfig
metadata:
  labels:
    my.label.selector/namespace-config: "mylabel"
  name: nginx-fbc
  namespace: <namespace_name>
spec:
  filterSelector:
    matchLabels:
      fluentbit.fluent.io/component: "nginx"
  parserSelector:
    matchLabels:
      fluentbit.fluent.io/component: "nginx"
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Filter
metadata:
  labels:
    fluentbit.fluent.io/component: "nginx"
  name: nginx-filter
  namespace: <namespace_name>
spec:
  filters:
    - parser:
        keyName: log
        reserveData: true
        preserveKey: true
        parser: nginx-parser1,nginx-parser2
  match: "kube.*ingress-nginx-controller*"
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Parser
metadata:
  labels:
    fluentbit.fluent.io/component: "nginx"
  name: nginx-parser1
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
    fluentbit.fluent.io/component: "nginx"
  name: nginx-parser2
  namespace: <namespace_name>
spec:
  json:
    timeKey: logtime
    timeKeep: true
    timeFormat: "%Y-%m-%dT%H:%M:%S+%L"
```

</div>
{{< /clipboard >}}

## Network Policies
NetworkPolicies let you specify how a pod is allowed to communicate with various network entities in a cluster. NetworkPolicies increase the security posture of the cluster by limiting network traffic and preventing unwanted network communication. NetworkPolicy resources affect layer 4 connections (TCP, UDP, and optionally SCTP). The cluster must be running a Container Network Interface (CNI) plug-in that enforces NetworkPolicies.

Verrazzano creates the following NetworkPolicy resource to only allow ingress to port 443 from all of the namespaces, and an ingress to port 10254 from Prometheus to scrape metrics. The manifest below assumes the Prometheus instance is installed using the Prometheus operator in the namespace `monitoring` with the label `myapp.io/namespace=monitoring`.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-nginx-controller
  namespace: ingress-nginx
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: controller
  policyTypes:
    - Ingress
  ingress:
    - ports:
        - port: 443
          protocol: TCP
    - ports:
        - port: 80
          protocol: TCP
    - ports:
        - port: 10254
          protocol: TCP
      from:
        - namespaceSelector:
            matchLabels:
              myapp.io/namespace: monitoring
          podSelector:
            matchLabels:
              app.kubernetes.io/name: prometheus
EOF
```
</div>
{{< /clipboard >}}

## Configure Prometheus scrape target for NGINX metrics

The section provides the steps to configure Prometheus scrape target for NGINX ingress controller metrics in using ServiceMonitor and PodMonitor. Both ServiceMonitor and PodMonitor declaratively specify how group of pods should be monitored. The Prometheus Operator automatically generates Prometheus scrape configuration based on the current state of the objects in the API server.

The instructions assume Prometheus is installed in `monitoring` namespace, using kube-prometheus-stack as documented in [Install Prometheus on OCNE]({{< relref "/docs/guides/migrate/install/prometheus/_index.md" >}}). The instructions also assume ingress-controller is installed using Helm, will change once it is installed as a CNE module.

### Prometheus metrics using ServiceMonitor

1. Configure ingress controller to enable metrics and creation of ServiceMonitor

   {{< clipboard >}}
   <div class="highlight">

   ```
   helm upgrade ingress-controller ingress-nginx/ingress-nginx \
      --namespace ingress-nginx \
      --set controller.metrics.enabled=true \
      --set controller.metrics.serviceMonitor.enabled=true \
      --set controller.metrics.serviceMonitor.additionalLabels.release="prometheus-operator" \
   ```

   </div>
   {{< /clipboard >}}
Here controller.metrics.serviceMonitor.additionalLabels.release="prometheus-operator" should match the name of the helm release of the `kube-prometheus-stack`.

### Prometheus metrics using PodMonitor

1. Configure ingress controller to enable metrics and export metrics

   {{< clipboard >}}
   <div class="highlight">

   ```
   helm upgrade ingress-controller ingress-nginx/ingress-nginx \
      --namespace ingress-nginx \
      --set controller.metrics.enabled=true \
      --set controller.metrics.portName=metrics \
      --set-string controller.podAnnotations."prometheus\.io/scrape"="true" \
      --set-string controller.podAnnotations."prometheus\.io/port"="10254"
   ```

   </div>
   {{< /clipboard >}}

1. Create a PodMonitor resource in `monitoring` namespace

   {{< clipboard >}}
   <div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: nginx-ingress-controller
  namespace: monitoring
  labels:
    release: prometheus-operator
spec:
  namespaceSelector:
    matchNames:
    - ingress-nginx
  selector: {}
  podMetricsEndpoints:
  - port: metrics
    enableHttp2: false
EOF
```

   </div>
   {{< /clipboard >}}
