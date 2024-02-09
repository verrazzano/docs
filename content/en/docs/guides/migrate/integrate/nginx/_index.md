---
title: "Ingress NGINX Controller"
weight: 1
draft: false
---
This document shows you how to integrate Ingress NGINX Controller with other OCNE components.

## Fluent Bit

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

### Prometheus Metrics using Service Monitor

1. Configure ingress controller to enable metrics and creation of Service Monitor

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
Here controller.metrics.serviceMonitor.additionalLabels.release="prometheus-operator" should match the name of the helm release of the kube-prometheus-stack.

### Prometheus Metrics using PodMonitor

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
