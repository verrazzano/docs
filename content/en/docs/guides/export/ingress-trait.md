---
title: "IngressTrait"
linkTitle: "IngressTrait"
description: "A guide for understanding the Kubernetes objects generated for an OAM IngressTrait"
weight: 5
draft: false
---

## IngressTrait (oam.verrazzano.io/v1alpha1)

Each IngressTrait will result in the creation of the following Kubernetes resources:
* networking.istio.io/v1beta1/Gateway
* networking.istio.io/v1beta1/VirtualService
* v1/Secret for the Gateway

For example, the following IngressTrait definition will result in the Gateway, VirtualService and Secret objects shown below.
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

#### Gateway
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
    - hello-helidon.hello-helidon.172.18.0.230.nip.io
    name: hello-helidon-ingress
    port:
      name: https-hello-helidon-ingress
      number: 443
      protocol: HTTPS
    tls:
      credentialName: hello-helidon-hello-helidon-ingress-cert-secret
      mode: SIMPLE
```

#### VirtualService
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
  - hello-helidon.hello-helidon.172.18.0.230.nip.io
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
#### Secret
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
    cert-manager.io/alt-names: hello-helidon.hello-helidon.172.18.0.230.nip.io
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