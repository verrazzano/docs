---
title: Customize Ingress
description: Customize Verrazzano NGINX and Istio ingress installation settings
linkTitle: Ingress
Weight: 9
draft: false
---

Verrazzano uses NGINX for ingress to Verrazzano system components and Istio for application ingress.
You can customize the NGINX and Istio ingress installation configurations using Helm overrides specified in the
Verrazzano custom resource. For example, the following Verrazzano custom resource overrides the shape
of an OCI load balancer for both NGINX and Istio ingress:

```shell
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: custom-lb-settings
spec:
  profile: prod
  components:
    ingress:
      type: LoadBalancer
      nginxInstallArgs:
      - name: controller.service.annotations."service\.beta\.kubernetes\.io/oci-load-balancer-shape"
        value: "10Mbps"
    istio:
      istioInstallArgs:
      - name: gateways.istio-ingressgateway.serviceAnnotations."service\.beta\.kubernetes\.io/oci-load-balancer-shape"
        value: "10Mbps"
```
