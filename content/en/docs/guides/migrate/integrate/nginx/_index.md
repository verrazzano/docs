---
title: "Ingress NGINX Controller"
weight: 1
draft: false
---
This document shows you how to integrate Ingress NGINX Controller with other OCNE components.

## Network Policies
NetworkPolicies let you specify how a pod is allowed to communicate with various network entities in a cluster. NetworkPolicies increase the security posture of the cluster by limiting network traffic and preventing unwanted network communication. NetworkPolicy resources affect layer 4 connections (TCP, UDP, and optionally SCTP). The cluster must be running a Container Network Interface (CNI) plug-in that enforces NetworkPolicies.

As an example, run the following command to apply NetworkPolicy resources to only allow ingress to port 443 from all the namespaces. Assuming the Prometheus instance is installed using the Prometheus operator in the namespace `monitoring` with the label `myapp.io/namespace=monitoring`, the network policy allows ingress to port 80 to scrape metrics.

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

## Prometheus
[Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/) exposes HTTP and HTTPS routes from outside the cluster to services within the cluster. Traffic routing is controlled by rules defined on the Ingress resource.
This section provides the steps to use ingress annotations with the ClusterIssuer to secure ingress to a Prometheus instance. Please go through the https://cert-manager.io/docs/ to read more about configuring issuers and annotated ingress resource.

The ingress will utilize the wildcard DNS service [nip.io](https://nip.io/) to create an address, that will forward requests to the Prometheus ClusterIP service. The nip.io service is a public DNS provider that will accept hostnames with an embedded IP address and return that address during name resolution. Please refer [Customize DNS]({{< relref "/docs/networking/traffic/dns.md" >}}) to understand the DNS choices.

1. Get the external IP of the ingress-controller service.

   {{< clipboard >}}
   <div class="highlight">

   ```
   $ kubectl get service --namespace ingress-nginx

   # Sample output
   NAME                                                    TYPE           CLUSTER-IP      EXTERNAL-IP    PORT(S)                      AGE
   ingress-controller-ingress-nginx-controller             LoadBalancer   10.96.238.164   172.18.0.241   80:32205/TCP,443:32714/TCP   4h13m
   ingress-controller-ingress-nginx-controller-admission   ClusterIP      10.96.114.143   <none>         443/TCP                      4h13m
   ```

   </div>
   {{< /clipboard >}}

1. Get the port on which the Prometheus instance is running.

   {{< clipboard >}}
   <div class="highlight">

   ```
   $ kubectl get -n monitoring prometheus

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

1. Create an Ingress that will forward requests to the Prometheus backend, where `my-cluster-issuer` is the name of an already created ClusterIssuer to acquire the certificate required for this Ingress.

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

1. Access Prometheus ingress endpoint using cURL

   {{< clipboard >}}
   <div class="highlight">

   ```
   $curl -k https://prometheus.172.18.0.241.nip.io

   # Sample output
   <a href="/graph">Found</a>.

   ```

   </div>
   {{< /clipboard >}}

   You can also access the Prometheus ingress endpoint using browser, by accepting the certificate. Please refer [FAQ]({{< relref "/docs/troubleshooting/FAQ.md" >}}) to understand the reason for accepting the self-signed certificates.
