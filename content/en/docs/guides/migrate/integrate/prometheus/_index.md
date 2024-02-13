---
title: "Prometheus"
weight: 1
draft: false
---
This document shows you how to integrate Prometheus with other OCNE components.

## Fluent Bit

## Ingress
Ingress exposes HTTP and HTTPS routes from outside the cluster to services within the cluster. Traffic routing is controlled by the rules defined on the Ingress resource. Please refer to [Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/) for more details.

The following instructions assume:
* Cert Manager is installed and a self-signed ClusterIssuer `my-cluster-issuer` is created
* The `kube-prometheus-stack` is installed in `monitoring` namespace, with Prometheus instance created be `prometheus-operator-kube-p-prometheus`, with a clusterIP service
* Ingress Controller is installed in `ingress-nginx` namespace

1. Obtain the external IP of the ingress-controller

   {{< clipboard >}}
   <div class="highlight">

   ```
   $kubectl get service -n ingress-nginx

   # Sample output
   NAME                                                    TYPE           CLUSTER-IP      EXTERNAL-IP    PORT(S)                      AGE
   ingress-controller-ingress-nginx-controller             LoadBalancer   10.96.238.164   172.18.0.241   80:32205/TCP,443:32714/TCP   4h13m
   ingress-controller-ingress-nginx-controller-admission   ClusterIP      10.96.114.143   <none>         443/TCP                      4h13m
   ```

   </div>
   {{< /clipboard >}}

1. Obtain the internal IP of the Prometheus Cluster IP service

   {{< clipboard >}}
   <div class="highlight">

   ```
   $kubectl get prometheus -n monitoring

   # Sample output
   NAME                                    VERSION                           DESIRED   READY   RECONCILED   AVAILABLE   AGE
   prometheus-operator-kube-p-prometheus   v2.44.0-20230922084259-74087370   1         1       True         True        3h55m

   $kubectl get service -n monitoring prometheus-operator-kube-p-prometheus

   # Sample output
   NAME                                    TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)    AGE
   prometheus-operator-kube-p-prometheus   ClusterIP   10.96.246.69   <none>        9090/TCP   3h56m
   ```

   </div>
   {{< /clipboard >}}

1. Create an Ingress to forward requests to the Prometheus backend, using cert-manager ingress annotations to create a TLS certificate for the endpoint signed by `my-cluster-issuer` ClusterIssuer


   {{< clipboard >}}
   <div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    cert-manager.io/cluster-issuer: my-cluster-issuer
    cert-manager.io/common-name: prometheus.172.18.0.241.nip.io
  name: prometheus
  namespace: monitoring
spec:
  ingressClassName: nginx
  rules:
  - host: prometheus.172.18.0.241.nip.io
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
    - prometheus.172.18.0.241.nip.io
    secretName: kube-prometheus-stack-prometheus-tls
EOF
```

   </div>
   {{< /clipboard >}}

The ingress in this case utilizes the wildcard DNS service [nip.io](https://nip.io/) to create an address, that will forward requests to the Prometheus ClusterIP service.

## Istio
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

