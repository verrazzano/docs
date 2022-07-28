---
title: Customize Prometheus
description: Customize Verrazzano Prometheus installation settings
linkTitle: Prometheus
Weight: 9
draft: false
---

Verrazzano installs Prometheus components, including Prometheus Operator and Prometheus, using the
[kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack) Helm chart.
You can customize the installation configuration using Helm overrides specified in the
Verrazzano custom resource. For example, the following Verrazzano custom resource overrides the number of Prometheus replicas.

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: custom-prometheus
spec:
  profile: prod
  components:
    prometheusOperator:
      overrides:
        - values:
            prometheus:
              prometheusSpec:
                replicas: 3
```

To enable Alertmanager, use the following Verrazzano custom resource:

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: custom-prometheus
spec:
  profile: prod
  components:
    prometheusOperator:
      overrides:
        - values:
            alertmanager:
              enabled: true
              alertmanagerSpec:
                podMetadata:
                  annotations:
                    sidecar.istio.io/inject: "false"
```

For more information about setting component overrides, see [Customizing the Chart Before Installing](https://helm.sh/docs/intro/using_helm/#customizing-the-chart-before-installing).
