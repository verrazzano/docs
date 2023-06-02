---
title: "Customize External Load Balancers"
description: "External load balancers for Verrazzano management and application endpoints"
weight: 3
draft: false
---

Verrazzano requires the following load balancers at installation:
* Load balancer for NGINX ingress
* Load balancer for Istio ingress

By default, Verrazzano automatically creates them as Kubernetes-managed load balancers, however,
you have the option to use your own external load balancers. You can choose to replace either or both load balancers.

The following is an example of using external load balancers for both management and application ingress.

### Prepare the external load balancers  

* External load balancer for management ingress:

  - This load balancer must have a listener set up on port `443` with `TCP` protocol.
  - The back end set for this listener needs to include the Kubernetes cluster node IP addresses on a port you pick, for example, `31443`.

* External load balancer for application ingress:

  - This load balancer must have a listener set up on port `443` with `TCP` protocol.
  - The back end set for this listener needs to include the Kubernetes cluster node IP addresses on a port you pick, for example, `32443`.

### Verrazzano installation options

* External load balancer for management ingress:

  - Set `NodePort` as the ingress type in the [Ingress Component]({{< relref "/docs/reference/vpo-verrazzano-v1beta1.md#install.verrazzano.io/v1beta1.IngressNginxComponent" >}}).
  - Set `controller.service.externalIPs` with the IP address for the external management load balancer in the [Ingress NGINX Overrides]({{< relref "/docs/reference/vpo-verrazzano-v1beta1#install.verrazzano.io/v1beta1.IngressNginxComponent" >}}).

    **NOTE**: If the ingress type is `NodePort`, then a valid and accessible IP address **must** be specified using the `controller.service.externalIPs` key in NGINXInstallArgs.

  - Set `ports` in the [Ingress Component]({{< relref "/docs/reference/vpo-verrazzano-v1beta1#install.verrazzano.io/v1beta1.IngressNginxComponent" >}}) with a [PortConfig](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#serviceport-v1-core) that has `443` as `port`, `31443` as `nodePort`, `https` as `targetPort`, and `TCP` as `protocol`.

* External load balancer for application ingress using the Istio ingress gateway overrides:

  - Set service Type to `NodePort`.
  - Set service `externalIPs` to the external application load balancer IP address.
  - Set service `ports` with a `https` named entry, `443` as `port`, `32443` as `nodePort`, `8443` as `targetPort`, and `TCP` as `protocol`.

### Example Custom Resource with management and application external load balancers
{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: myvz
spec:
  components:
    ingressNGINX:
      overrides:
      - values:
          controller:
            service:
              externalIPs:
              - 11.22.33.44
      type: NodePort
      ports:
      - name: https
        port: 443
        nodePort: 31443
        protocol: TCP
        targetPort: https
    istio:
      overrides:
      - values:
          apiVersion: install.istio.io/v1alpha1
          kind: IstioOperator
          spec:
            components:
              ingressGateways:
                - enabled: true
                  name: istio-ingressgateway
                  k8s:
                    service:
                      type: NodePort
                      ports:
                      - name: https
                        port: 443
                        nodePort: 32443
                        protocol: TCP
                        targetPort: 8443
                      externalIPs:
                      - 11.22.33.55
```

</div>
{{< /clipboard >}}
