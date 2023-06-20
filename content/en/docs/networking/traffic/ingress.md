---
title: Customize Ingress
description: Customize Verrazzano NGINX and Istio ingress settings
Weight: 4
draft: false
aliases:
  - /docs/customize/ingress
---

Verrazzano uses NGINX for ingress to Verrazzano system components and Istio for application ingress.
You can customize the NGINX and Istio ingress installation configurations using Helm overrides specified in the
Verrazzano custom resource. For example, the following Verrazzano custom resource overrides the shape
of an Oracle Cloud Infrastructure load balancer for both NGINX and Istio ingresses.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: custom-lb-settings
spec:
  profile: prod
  components:
    ingressNGINX:
      type: LoadBalancer
      overrides:
      - values:
          controller:
            service:
              annotations:
                service.beta.kubernetes.io/oci-load-balancer-shape: flexible
                service.beta.kubernetes.io/oci-load-balancer-shape-flex-max: "100"
                service.beta.kubernetes.io/oci-load-balancer-shape-flex-min: "100"
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
                      service.beta.kubernetes.io/oci-load-balancer-shape: flexible
                      service.beta.kubernetes.io/oci-load-balancer-shape-flex-max: "100"
                      service.beta.kubernetes.io/oci-load-balancer-shape-flex-min: "100"
```


</div>
{{< /clipboard >}}

For more information about setting component overrides, see [Customizing the Chart Before Installing](https://helm.sh/docs/intro/using_helm/#customizing-the-chart-before-installing).
