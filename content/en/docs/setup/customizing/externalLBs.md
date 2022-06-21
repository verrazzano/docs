---
title: "External Load Balancers"
description: "External load balancers for Verrazzano management and application endpoints"
linkTitle: External Load Balancers
weight: 11
draft: false
---

Verrazzano requires the following load balancers at installation:
* Load balancer for NGINX ingress
* Load balancer for Istio ingress

By default, Verrazzano automatically creates them as Kubernetes managed load balancers. 

However, users do have the options to use their own external load balancers.  They can pick and choose to replace either or both load balancers.

The following is an example of using external load balancers for both management and application ingress.

### Prepare the external load balancers  

* External load balancer for management ingress

  - This load balancer must have a listener set up on port `443` with `TCP` protocol.
  - The backend set for this listener needs to include the Kubernetes cluster node IP addresses on a port you pick, for example, `31443`.

* External load balancer for application ingress

  - This load balancer must have a listener set up on port `443` with `TCP` protocol.
  - The backend set for this listener needs to include the Kubernetes cluster node IP addresses on a port you pick, for example, `32443`.

### Verrazzano installation options

* External load balancer for management ingress

  - Set `NodePort` as the ingress type in [Ingress Component]({{< relref "/docs/reference/API/Verrazzano/Verrazzano.md#ingress-component" >}}).
  - Set `controller.service.externalIPs` with the IP address for the external management load balancer in [NGINX Install Args]({{< relref "/docs/reference/API/Verrazzano/Verrazzano.md#nginx-install-args" >}}).
  - Set `ports` in [Ingress Component]({{< relref "/docs/reference/API/Verrazzano/Verrazzano.md#ingress-component" >}}) with a [PortConfig]({{< relref "/docs/reference/API/Verrazzano/Verrazzano.md#port-config" >}}) that has `443` as `port`, `31443` as `nodePort`, `https` as `targetPort`, and `TCP` as `protocol`.

* External load balancer for application ingress

  - Set `NodePort` as the Istio ingress type in [Istio Ingress Configuration]({{< relref "/docs/reference/API/Verrazzano/Verrazzano.md#istio-ingress-configuration" >}}).
  - Set `gateways.istio-ingressgateway.externalIPs` with the IP address for the external application load balancer in [Istio Install Args]({{< relref "/docs/reference/API/Verrazzano/Verrazzano.md#istio-install-args" >}}).
  - Set `ports` in [Istio Ingress Configuration]({{< relref "/docs/reference/API/Verrazzano/Verrazzano.md#istio-ingress-configuration" >}}) with a [PortConfig]({{< relref "/docs/reference/API/Verrazzano/Verrazzano.md#port-config" >}}) that has `443` as `port`, `32443` as `nodePort`, `8443` as `targetPort`, and `TCP` as `protocol`.

### Example Custom Resource with management and application external load balancers

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: myvz
spec:
  components:
    ingress:
      type: NodePort
      ports:
      - name: https
        port: 443
        nodePort: 31443
        protocol: TCP
        targetPort: https
      nginxInstallArgs:
      - name: controller.service.externalIPs
        valueList:
        - 11.22.33.44
    istio:
      ingress:
        type: NodePort
        ports:
        - name: https
          port: 443
          nodePort: 32443
          protocol: TCP
          targetPort: 8443
      istioInstallArgs:
      - name: gateways.istio-ingressgateway.externalIPs
        valueList:
        - 55.66.77.88
```