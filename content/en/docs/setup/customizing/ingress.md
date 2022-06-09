---
title: Customize Ingress
description: Customize Verrazzano NGINX and Istio ingress installation settings
linkTitle: Ingress
Weight: 9
draft: false
---

Verrazzano uses NGINX for ingress to Verrazzano system components.
You can customize the NGINX configuration using Overrides specified in the Verrazzano custom resource. 
[Overrides](({{< relref "/docs/reference/API/Verrazzano/Verrazzano.md#override" >}})) can be specified as inline YAML
or embedded in a ConfigMap or Secret.
For example, the following Verrazzano custom resource overrides the autoscaling
configuration for the NGINX ingress controller.

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: custom-lb-settings
spec:
  profile: prod
  components:
    ingress:
      type: LoadBalancer
      overrides:
      - values:
          controller:
            autoscaling:
              enabled: "true"
              minReplicas: 3
```

For more information about setting component overrides, see [Customizing the Chart Before Installing](https://helm.sh/docs/intro/using_helm/#customizing-the-chart-before-installing).

NGINX values available for customizing can be found in the `values.yaml` file in the [ingress-nginx Helm Chart](https://github.com/verrazzano/verrazzano/blob/master/platform-operator/thirdparty/charts/ingress-nginx/values.yaml)