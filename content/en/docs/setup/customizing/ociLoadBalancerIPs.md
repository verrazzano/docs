---
title: "Customizing Load Balancers on OKE"
description: "Customizing load balancers on OKE for Verrazzano system and application endpoints"
linkTitle: OKE Load Balancers
weight: 3
draft: false
---

Verrazzano sets up the following load balancers on Kubernetes at install time:
* Loadbalancer for NGINX ingress
* Loadbalancer for Istio ingress

Verrazzano allows customizing the LoadBalancers allocated by Oracle Container Engine (OKE) using annotations defined by OKE.

### Customizing LoadBalancer Shape  

At the time of installation Verrazzano allows users to customize the shape and size of the load balancers created. 
OCI offers a flexible LoadBalancer which uses Dynamic Shape: 
* 10 Mbps
* 100 Mbps 
* 400 Mbps
* 8,000 Mbps

More details on service limits and shape can be found [here](https://docs.oracle.com/en-us/iaas/Content/Balance/Tasks/managingloadbalancer.htm#console).

For example, setting up NGINX load balancer with `10Mbps` can be achieved as follows:

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

For example, setting up Istio load balancer with `10Mbps` can be achieved as follows:

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

### Using PRIVATE ip addresses with LoadBalancer

At the time of installation Verrazzano allows users to customize the ip address of load balancers created.

For example, setting up NGINX to have a PRIVATE load balancer ip while the Istio load balancer is assigned a PUBLIC ip:

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
```

Example of setting up NGINX to have a PUBLIC load balancer ip while the Istio load balancer is assigned a PRIVATE ip:

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
```

Example of setting both NGINX and Istio to have a PRIVATE load balancer ips:

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
    istio:
      istioInstallArgs:
      - name: gateways.istio-ingressgateway.serviceAnnotations."service\.beta\.kubernetes\.io/oci-load-balancer-internal"
        value: "true"
```
