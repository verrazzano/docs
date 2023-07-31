---
title: "Alertmanager"
description: "Customize Alertmnager to alert on Verrazzano"
weight: 2
draft: false
aliases:
- /docs/customize/alertmanager
- /docs/observability/monitoring/configure/alertmanager
---
Alertmanager is used in conjunction with Prometheus to send alerts about the state of your clusters.
You can create PrometheusRules that will trigger alerts based on the value of metrics.
Alertmanager provides integrations for email, Slack, PagerDuty, and other popular notification services to receive alerts.

## Enable Alertmanager

To enable Alertmanager, configure it from the Prometheus Operator component
in the Verrazzano custom resources.
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
   ```

</div>
{{< /clipboard >}}

## Create an AlertmanagerConfig


Next, create an AlertmanagerConfig to configure the receivers that Alertmanager will send alerts to.
To create the AlertmanagerConfig, access the Verrazzano console and navigate to the following location.

**Monitoring** > **Alerting** > **AlertmanagerConfigs**.

Alertmanager will automatically discover AlertmanagerConfigs in the same namespace,
which by default in Verrazzano is `verrazzano-monitoring`.

## Customize the AlertmanagerConfig namespace

If you would prefer to create the AlertmanagerConfig
in a different namespace, you can configure Alertmanager to discover AlertmanagerConfig resouces
in other namespaces using labels.
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
                   alertmanagerConfigNamespaceSelector:
                     matchLabels:
                       namespace-label: my-app
   ```

</div>
{{< /clipboard >}}

For more information about Alertmanager configurations, see the [Alertmanager Documentation](https://prometheus.io/docs/alerting/latest/configuration/).

## Deploy a PrometheusRule

After you have enabled Alertmanager and configured an AlertmanagerConfig with a receiver and route,
you can deploy rules on which to receive alerts.
To create a `TestAlertRule`, run the following command.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
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
</div>
{{< /clipboard >}}

For more information, see [Deploying Prometheus Rules](https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/user-guides/alerting.md#deploying-prometheus-rules).
