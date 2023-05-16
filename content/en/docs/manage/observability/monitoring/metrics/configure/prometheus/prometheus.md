---
title: "Prometheus"
linkTitle: Prometheus
description: "Learn how to customize Prometheus to monitor Verrazzano"
weight: 1
draft: false
---
Prometheus is a system for monitoring cloud native applications and is used by Verrazzano to monitor applications. Prometheus is used in Verrazzano to collect system performance metrics and applications deployed or managed by Verrazzano. Prometheus analysis the metrics and provide a visualization using Grafana.

Verrazzano installs Prometheus components, including Prometheus Operator and Prometheus, using the
[kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack) Helm chart.
You can customize the installation configuration using Helm overrides specified in the
Verrazzano custom resource. For example, the following Verrazzano custom resource overrides the number of Prometheus replicas.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
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
</div>
{{< /clipboard >}}

To enable Alertmanager, use the following Verrazzano custom resource:
{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
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

</div>
{{< /clipboard >}}

For more information about setting component overrides, see [Customizing the Chart Before Installing](https://helm.sh/docs/intro/using_helm/#customizing-the-chart-before-installing).

After you have enabled Alertmanager, you can deploy alert rules to get proactive alerts.
To create a `TestAlertRule`, run the following command.
```yaml
kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  labels:
    release: prometheus-operator
  name: prometheus-operator-test
  namespace: verrazzano-monitoring
spec:
  groups:
    - name: test
      rules:
        - alert: TestAlertRule
          annotations:
            description: Test alert rule
            runbook_url: test-runbook-url
            summary: Test alert rule
          expr: |-
            prometheus_config_last_reload_successful{job="prometheus-operator-kube-p-prometheus",namespace="verrazzano-monitoring"} == 0
          for: 10m
          labels:
            severity: critical
EOF
```
For more information, see [Deploying Prometheus rules](https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/user-guides/alerting.md#deploying-prometheus-rules).
