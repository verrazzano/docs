---
title: "Customizing Load Balancers on OKE"
description: "Customizing Load Balancers on OKE for Verrazzano system and application endpoints"
linkTitle: OKELoadBalancer
weight: 1
draft: false
---

Verrazzano sets up the following Load Balancers on Kuberentes at install time:
* LoadBalancer for Nginx ingress
* LoadBalancer for Istio ingress

Verrazzano allows customizing the LoadBalancers allocated by Oracle Container Engine (OKE) using annotations defined by OKE.

### Customizing LoadBalancer Shape  

At the time of installation Verrazzano allows users to customize the shape and size of the LoadBalancers created. 
OCI offers a flexible LoadBalancer which uses Dynamic Shape 
* 10 Mbps
* 100 Mbps 
* 400 Mbps
* 8,000 Mbps

More details on service limits and shape can be found [here](https://docs.oracle.com/en-us/iaas/Content/Balance/Tasks/managingloadbalancer.htm#console)

For example, setting up Nginx LoadBalancer with `10Mbps` can be achieved as follows:

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

For example, setting up Istio LoadBalancer with `10Mbps` can be achieved as follows:

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
        value: "10Mbps 
```

### Using PRIVATE ip addresses with LoadBalancer

At the time of installation Verrazzano allows users to customize the ip address of LoadBalancers created.

For example, setting up Nginx to have a PRIVATE LoadBalancer ip while the Istio LoadBalancer is assigned a PUBLIC ip:

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

Example of setting up Nginx to have a PUBLIC LoadBalancer ip while the Istio LoadBalancer is assigned a PRIVATE ip:

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

Example of setting both Nginx and Istio to have a PRIVATE LoadBalancer ips:

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
