---
title: "IngressTrait"
linkTitle: "IngressTrait"
description: "A guide for understanding how Kubernetes objects are generated for an OAM IngressTrait"
weight: 5
draft: false
---

## IngressTrait (oam.verrazzano.io/v1alpha1)

Each IngressTrait will result in the creation of the following objects:
* networking.istio.io/v1beta1/Gateway
* networking.istio.io/v1beta1/VirtualService
* A Secret for the Gateway

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
