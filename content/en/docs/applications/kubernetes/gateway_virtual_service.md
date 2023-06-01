---
title: "Istio Gateway and Virtual Service"
description: "Learn about Istio gateway and virtual service"
weight: 4
draft: false
---

### Istio gateway
A gateway is a load balancer that connects to the mesh and receives incoming or outgoing HTTP/TCP connections. It specifies which ports are to be exposed, the protocol to be used, and so on.

The following is an example to direct public access to the Hello Helidon Greet application.
Replace _domain name_ with the Kubernetes cluster domain used in Verrazzano. This ensures that you have a fully-qualified domain name for host entries in the resources.

{{< clipboard >}}
<div class="highlight">

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
    - hello-helidon.hello-helidon.<domain name>
    name: hello-helidon-ingress
    port:
      name: https-hello-helidon-ingress
      number: 443
      protocol: HTTPS
    tls:
      credentialName: hello-helidon-hello-helidon-ingress-cert-secret # Secret that contains the certificate used for TLS
      mode: SIMPLE
```
</div>
{{< /clipboard >}}

### Istio virtual service

A virtual service helps in connecting the gateway to the Kubernetes service. It is a set of rules for routing traffic based on the match criteria for a specific protocol. If the traffic matches the criteria, then it will be sent to a named destination service.   

The following is an example of registering the Hello Helidon Greet application in the Istio service registry.  
Replace _domain name_ with the Kubernetes cluster domain used in Verrazzano. This ensures that you have a fully-qualified domain name for host entries in the resources.

{{< clipboard >}}
<div class="highlight">

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
- hello-helidon.hello-helidon.<domain name>
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
</div>
{{< /clipboard >}}
