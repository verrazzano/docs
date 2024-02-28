---
title: "OpenSearch"
weight: 1
draft: false
---
This document shows you how to integrate OpenSearch with other OCNE components.

## Network Policies

## Ingress
Ingress exposes HTTP and HTTPS routes from outside the cluster to services within the cluster. Traffic routing is controlled by the rules defined on the Ingress resource. Please refer to [Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/) for more details.

#### Create Ingress to forward requests to OpenSearch and OpenSearch Dashboards
The following example creates two Ingress to forward requests to the OpenSearch and OpenSearch Dashboards backend, using cert-manager ingress annotations to create a TLS certificate for the endpoint signed by `my-cluster-issuer` ClusterIssuer.

The instructions assume:
1. Cert Manager is installed and a ClusterIssuer `my-cluster-issuer` is created
2. The `openSearch` and `OpenSearch Dashboards` are installed in `logging` namespace.
3. The OpenSearch instance is listening on default port `9200` and OpenSearch Dashboards is listening on default port `5601`.
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
    cert-manager.io/common-name: os.10.0.0.1.nip.io
  name: opensearch
  namespace: logging
spec:
  ingressClassName: nginx
  rules:
  - host: os.10.0.0.1.nip.io
    http:
      paths:
      - backend:
          service:
            name: opensearch
            port:
              number: 9200
        path: /()(.*)
        pathType: Prefix
  tls:
  - hosts:
    - opensearch.10.0.0.1.nip.io
    secretName: opensearch-tls
EOF
```

   </div>
   {{< /clipboard >}}

{{<clipboard >}}
   <div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    cert-manager.io/cluster-issuer: my-cluster-issuer
    cert-manager.io/common-name: osd.10.0.0.1.nip.io
  name: opensearch-dashboards
  namespace: logging
spec:
  ingressClassName: nginx
  rules:
  - host: osd.10.0.0.1.nip.io
    http:
      paths:
      - backend:
          service:
            name: opensearch-dashboards
            port:
              number: 5601
        path: /()(.*)
        pathType: Prefix
  tls:
  - hosts:
    - opensearch.10.0.0.1.nip.io
    secretName: opensearch-dashboards-tls
EOF
```

   </div>
   {{< /clipboard >}}

The ingress in this case utilizes the wildcard DNS service [nip.io](https://nip.io/) to create an address, that will forward requests to the OpenSearch or OpenSearch Dashboards ClusterIP services.
## Istio
## Prometheus

Apply the following `ServiceMonitor` resource to scrape metrics from OpenSearch pods. This assumes Prometheus Operator has been installed in the `monitoring` namespace and OpenSearch & OpenSearch Dashboards has been installed in the `logging` namespace.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: opensearch
  namespace: monitoring
  labels:
    release: prometheus-operator
spec:
  namespaceSelector:
    matchNames:
      - logging
  selector: {}
  endpoints:
    - path: /_prometheus/metrics
      enableHttp2: false
      tlsConfig:
        ca:
          secret:
            name: opensearch-monitor-certs
            key: ca.crt
        cert:
          secret:
            name: opensearch-monitor-certs
            key: tls.crt
        keySecret:
          name: opensearch-monitor-certs
          key: tls.key
        insecureSkipVerify: true
      scheme: https
      relabelings:
        - sourceLabels:
            - __meta_kubernetes_pod_name
          regex: opensearch.*
          action: keep
        - sourceLabels:
            - __meta_kubernetes_pod_container_port_number
          regex: "9200"
          action: keep
        - sourceLabels:
            - __meta_kubernetes_namespace
          action: replace
          targetLabel: namespace
        - sourceLabels:
            - __meta_kubernetes_pod_name
          action: replace
          targetLabel: kubernetes_pod_name
```
</div>
{{< /clipboard >}}

This `ServiceMonitor` assumes OpenSearch is running in the Istio mesh. If OpenSearch is not in the Istio mesh, then remove the `tlsConfig` and change the `scheme` to `http`.

## Cert-Manager
