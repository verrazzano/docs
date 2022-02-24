---
title: "Customize Load Balancers on OKE"
description: "Customize load balancers on OKE for Verrazzano system and application endpoints"
linkTitle: OKE Load Balancers
weight: 3
draft: false
---

Verrazzano sets up the following load balancers on Kubernetes at installation:
* Load balancer for NGINX ingress
* Load balancer for Istio ingress

Verrazzano allows customizing the load balancers allocated by Oracle Container Engine (OKE) using annotations defined by OKE.
You can find a detailed discussion of the different load balancer customization annotations in the OKE documentation
[here](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengcreatingloadbalancer.htm).

This document describes how to use these annotations to customize the following settings for Verrazzano load balancers:
* Load balancer shape
* Private IP address and subnet placement

### Customize the load balancer shape  

At installation, Verrazzano lets you customize the shape and size of the load balancers created.
OCI offers a flexible load balancer which uses Dynamic Shape:
* 10 Mbps
* 100 Mbps
* 400 Mbps
* 8,000 Mbps

For more details on service limits and shape, see [here](https://docs.oracle.com/en-us/iaas/Content/Balance/Tasks/managingloadbalancer.htm#console).

For example, you can set up an NGINX load balancer with `10Mbps` as follows:

```yaml
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  environmentName: default
  components:
    ingress:
      type: LoadBalancer
      nginxInstallArgs:
      - name: controller.service.annotations."service\.beta\.kubernetes\.io/oci-load-balancer-shape"
        value: "10Mbps"   
```

For example, you can set up an Istio load balancer with `10Mbps` as follows:

```yaml
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  environmentName: default
  components:
    ingress:
      type: LoadBalancer
      istioInstallArgs:
      - name: gateways.istio-ingressgateway.serviceAnnotations."service\.beta\.kubernetes\.io/oci-load-balancer-shape"
        value: "10Mbps"
```

### Using private IP addresses with a load balancer

At installation, Verrazzano lets you customize the IP address and subnet of the load balancers created.  This is achieved
using OKE annotations on the NGINX and Istio load balancer services, as documented 
[here](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengcreatingloadbalancer.htm#Creating2).

The following example configures the NGINX load balancer service to have a private load balancer IP address on the 
private subnet identified by OCID `ocid1.subnet.oc1.phx.aaaa..sdjxa`, and uses the default (public) load balancer 
configuration for Istio:

```yaml
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  environmentName: default
  components:
    ingress:
      type: LoadBalancer
      nginxInstallArgs:
      - name: controller.service.annotations."service\.beta\.kubernetes\.io/oci-load-balancer-internal"
        value: "true"    
      - name: controller.service.annotations."service\.beta\.kubernetes\.io/oci-load-balancer-subnet1"
        value: "ocid1.subnet.oc1.phx.aaaa..sdjxa"
```

The following example configures the Istio ingress gateway service to have a private load balancer IP address on the private 
subnet identified by OCID `ocid1.subnet.oc1.phx.aaaa..sdjxa`, and uses the default (public) load balancer configuration 
for NGINX:

```yaml
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  environmentName: default
  components:
    ingress:
      type: LoadBalancer      
    istio:
      istioInstallArgs:
        - name: gateways.istio-ingressgateway.serviceAnnotations."service\.beta\.kubernetes\.io/oci-load-balancer-internal"
          value: "true"
        - name: gateways.istio-ingressgateway.serviceAnnotations."service\.beta\.kubernetes\.io/oci-load-balancer-subnet1"
          value: "ocid1.subnet.oc1.phx.aaaa..sdjxa"
```

The following example configures both NGINX and Istio to have a private load balancer IP address on the private subnet 
identified by OCID `ocid1.subnet.oc1.phx.aaaa..sdjxa`:

```yaml
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  environmentName: default
  components:
    ingress:
      type: LoadBalancer
      nginxInstallArgs:
      - name: controller.service.annotations."service\.beta\.kubernetes\.io/oci-load-balancer-internal"
        value: "true"
      - name: controller.service.annotations."service\.beta\.kubernetes\.io/oci-load-balancer-subnet1"
        value: "ocid1.subnet.oc1.phx.aaaa..sdjxa"
    istio:
      istioInstallArgs:
      - name: gateways.istio-ingressgateway.serviceAnnotations."service\.beta\.kubernetes\.io/oci-load-balancer-internal"
        value: "true"
      - name: gateways.istio-ingressgateway.serviceAnnotations."service\.beta\.kubernetes\.io/oci-load-balancer-subnet1"
        value: "ocid1.subnet.oc1.phx.aaaa..sdjxa"
```
