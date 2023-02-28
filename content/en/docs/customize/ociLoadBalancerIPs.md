---
title: "Load Balancers on OCI"
description: "Customize load balancers on OCI for Verrazzano system and application endpoints"
linkTitle: OCI Load Balancers
weight: 9
draft: false
---

Verrazzano sets up the following load balancers on Kubernetes at installation:
* Load balancer for NGINX ingress
* Load balancer for Istio ingress

Verrazzano allows customizing the load balancers allocated by Oracle Cloud Infrastructure (OCI) using annotations defined by
the  OCI Cloud Controller Manager (OCI-CCM).  For a detailed description of different load balancer customization annotations, see the
documentation [here](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengcreatingloadbalancer.htm).

This document describes how to use these annotations to customize the following settings for Verrazzano load balancers:
* Load balancer shape
* Private IP address and subnet placement

### Customize the load balancer shape  

At installation, Verrazzano lets you customize the shape and size of the load balancers created.
Oracle Cloud Infrastructure offers a flexible load balancer which uses Dynamic Shape:
* 10 Mbps
* 100 Mbps
* 400 Mbps
* 8,000 Mbps

For more details on service limits and shape, see [here](https://docs.oracle.com/en-us/iaas/Content/Balance/Tasks/managingloadbalancer.htm#console).

For example, you can set up an NGINX load balancer with `10Mbps` as follows:
{{< clipboard >}}

```yaml
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  components:
    ingressNGINX:
      type: LoadBalancer
      overrides:
        - values:
            controller:
              service:
                annotations:
                  service.beta.kubernetes.io/oci-load-balancer-shape: 10Mbps
```

{{< /clipboard >}}

For example, you can set up an Istio load balancer with `10Mbps` as follows:
{{< clipboard >}}

```yaml
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  components:
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
                      serviceAnnotations:
                        service.beta.kubernetes.io/oci-load-balancer-shape: 10Mbps
```
{{< /clipboard >}}
### Use private IP addresses with a load balancer

At installation, Verrazzano lets you customize the IP address and subnet of the load balancers created.  This is achieved
using OCI-CCM annotations on the NGINX and Istio load balancer services, as documented
[here](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengcreatingloadbalancer.htm#Creating2).

The following example configures the NGINX load balancer service to have a private load balancer IP address on the
private subnet identified by the OCID `ocid1.subnet.oc1.phx.aaaa..sdjxa`, and uses the default (public) load balancer
configuration for Istio.
{{< clipboard >}}

```yaml
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  components:
    ingressNGINX:
      type: LoadBalancer
      overrides:
        - values:
            controller:
              service:
                annotations:
                  service.beta.kubernetes.io/oci-load-balancer-internal: "true"
                  service.beta.kubernetes.io/oci-load-balancer-subnet1: "ocid1.subnet.oc1.phx.aaaa..sdjxa"
```
{{< /clipboard >}}
The following example configures the Istio ingress gateway service to have a private load balancer IP address on the private
subnet identified by the OCID `ocid1.subnet.oc1.phx.aaaa..sdjxa`, and uses the default (public) load balancer configuration
for NGINX.
{{< clipboard >}}

```yaml
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  components:  
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
                      serviceAnnotations:
                        service.beta.kubernetes.io/oci-load-balancer-internal: "true"
                        service.beta.kubernetes.io/oci-load-balancer-subnet1: "ocid1.subnet.oc1.phx.aaaa..sdjxa"
```
{{< /clipboard >}}

The following example configures both NGINX and Istio to have a private load balancer IP address on the private subnet
identified by the OCID `ocid1.subnet.oc1.phx.aaaa..sdjxa`.
{{< clipboard >}}

```yaml
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  components:
    ingressNGINX:
      type: LoadBalancer
      overrides:
        - values:
            controller:
              service:
                annotations:
                  service.beta.kubernetes.io/oci-load-balancer-internal: "true"
                  service.beta.kubernetes.io/oci-load-balancer-subnet1: "ocid1.subnet.oc1.phx.aaaa..sdjxa"
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
                      serviceAnnotations:
                        service.beta.kubernetes.io/oci-load-balancer-internal: "true"
                        service.beta.kubernetes.io/oci-load-balancer-subnet1: "ocid1.subnet.oc1.phx.aaaa..sdjxa"
```
{{< /clipboard >}}
