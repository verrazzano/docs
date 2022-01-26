---
title: "Customize OCI LoadBalancer IP Address"
description: "Customize OCI LoadBalancer IP Address for Verrazzano system and application endpoints"
linkTitle: OCILoadBalancer
weight: 1
draft: false
---

Verrazzano sets up the following Load Balancers on Kuberentes at install time:
* LoadBalancer for Nginx ingress
* LoadBalancer for Istio ingress

Verrazzano allows customizing the system LoadBalancers with OCI to provide a combination of public and private ip addresses. 
This is achieved at install time by specifying OCI specific annotations.


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
