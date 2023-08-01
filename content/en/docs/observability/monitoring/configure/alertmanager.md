---
title: "Alertmanager"
description: "Customize Alertmanager alerting"
weight: 2
draft: false
aliases:
- /docs/customize/alertmanager
- /docs/observability/monitoring/configure/alertmanager
---
Alertmanager sends alerts that are firing in Prometheus to configured receivers. PrometheusRules installed in the cluster
will trigger alerts based on the value of metrics. Alertmanager will group, route, and silence
these alerts according to its installed configuration.
Alertmanager provides receiver integrations for email, Slack, PagerDuty, and other popular notification services.

## Enable Alertmanager

To enable Alertmanager, configure it from the Prometheus Operator component
in the Verrazzano custom resource.
{{< clipboard >}}
<div class="highlight">

   ```
   apiVersion: install.verrazzano.io/v1beta1
   kind: Verrazzano
   metadata:
     name: custom-prometheus
   spec:
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

**Monitoring** > **Alerting** > **AlertmanagerConfigs**

Alertmanager will automatically discover AlertmanagerConfigs in the same namespace where it is deployed,
which by default in Verrazzano is `verrazzano-monitoring`.

For more information about Alertmanager configurations, see the [Alertmanager Documentation](https://prometheus.io/docs/alerting/latest/configuration/).

## Deploy a PrometheusRule

After you have enabled Alertmanager and configured an AlertmanagerConfig with a receiver and route,
you can deploy rules that will trigger alerts.
To create a `TestAlertRule`, run the following command.
This PrometheusRule will alert if the last config reload in the Prometheus pod was unsuccessful.
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
