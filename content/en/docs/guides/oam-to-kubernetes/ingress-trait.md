---
title: "IngressTrait"
linkTitle: "IngressTrait"
description: "Review the Kubernetes resources Verrazzano creates for an OAM IngressTrait"
weight: 5
draft: false
---

Verrazzano generates the following Kubernetes resources for an [IngressTrait]({{< relref "/docs/applications/oam/traits/ingress/ingress.md" >}}):
* networking.istio.io/v1beta1/VirtualService - Implements the `rules` portion of the IngressTrait.
* networking.istio.io/v1beta1/Gateway - Defines the ingress for traffic management for the application running within the Istio mesh.
* security.istio.io/v1/AuthorizationPolicy - The authorization policy to secure access to the application.
* v1/Secret for the Gateway - The credential for the server TLS settings.

For example, the following IngressTrait is defined for the component, `hello-helidon-component`, of the [Hello World Helidon]({{< relref "/docs/examples/hello-helidon/_index.md" >}}) example.
```
apiVersion: oam.verrazzano.io/v1alpha1
kind: IngressTrait
metadata:
  name: hello-helidon-ingress
spec:
  rules:
    - paths:
        - path: "/greet"
          pathType: Prefix
      destination:
        port: 8080
```

A VirtualService resource, similar to the following one, will be created.
```
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: hello-helidon-ingress-rule-0-vs
  namespace: hello-helidon
spec:
  gateways:
  - hello-helidon-hello-helidon-gw
  hosts:
  - hello-helidon.hello-helidon.11.22.0.230.nip.io
  http:
  - match:
    - uri:
        prefix: /greet
    route:
    - destination:
        host: hello-helidon-deployment
        port:
          number: 8080
```

A Gateway resource, similar to the following one, will be created.
```
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: hello-helidon-hello-helidon-gw
  namespace: hello-helidon
spec:
  selector:
    istio: ingressgateway
  servers:
  - hosts:
    - hello-helidon.hello-helidon.11.22.0.230.nip.io
    name: hello-helidon-ingress
    port:
      name: https-hello-helidon-ingress
      number: 443
      protocol: HTTPS
    tls:
      credentialName: hello-helidon-hello-helidon-ingress-cert-secret
      mode: SIMPLE
```
An AuthorizationPolicy resource, similar to the following one, will be created.
```
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  labels:
    verrazzano.io/istio: hello-helidon
  name: hello-helidon
  namespace: hello-helidon
spec:
  rules:
  - from:
    - source:
        principals:
        - cluster.local/ns/hello-helidon/sa/hello-helidon
        - cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account
        - cluster.local/ns/verrazzano-system/sa/verrazzano-monitoring-operator
        - cluster.local/ns/verrazzano-monitoring/sa/prometheus-operator-kube-p-prometheus
  selector:
    matchLabels:
      verrazzano.io/istio: hello-helidon
```

A Secret resource, similar to the following one, will be created in the `istio-system` namespace.
```
apiVersion: v1
kind: Secret
data:
  ca.crt:
    <base64 encoding of CA certificate data>
  tls.crt:     
    <base64 encoding of TLS certificate data>
  tls.key:
    <base64 encoding of key data>
metadata:
  annotations:
    cert-manager.io/alt-names: hello-helidon.hello-helidon.11.22.0.230.nip.io
    cert-manager.io/certificate-name: hello-helidon-hello-helidon-ingress-cert
    cert-manager.io/common-name: ""
    cert-manager.io/ip-sans: ""
    cert-manager.io/issuer-group: ""
    cert-manager.io/issuer-kind: ClusterIssuer
    cert-manager.io/issuer-name: verrazzano-cluster-issuer
    cert-manager.io/uri-sans: ""
  name: hello-helidon-hello-helidon-ingress-cert-secret
  namespace: istio-system
type: kubernetes.io/tls
```
