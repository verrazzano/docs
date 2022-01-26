---
title: "Customizing Load Balancers on OKE"
descrIP addresstion: "Customizing load balancers on OKE for Verrazzano system and application endpoints"
linkTitle: OKE Load Balancers
weight: 3
draft: false
---

Verrazzano sets up the following load balancers on Kubernetes at install time:
* Load balancer for NGINX ingress
* Load balancer for Istio ingress

Verrazzano allows customizing the load balancers allocated by Oracle Container Engine (OKE) using annotations defined by OKE.

### Customizing load balancer shape  

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

### Using PRIVATE IP address with load balancer

At installation, Verrazzano lets you customize the IP address of the load balancers created.

For example, setting up NGINX to have a PRIVATE load balancer IP address while the Istio load balancer is assigned a PUBLIC IP address:

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

Example of setting up NGINX to have a PUBLIC load balancer IP address while the Istio load balancer is assigned a PRIVATE IP address:

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

Example of setting both NGINX and Istio to have a PRIVATE load balancer IP address:

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
