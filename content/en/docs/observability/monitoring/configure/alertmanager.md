---
title: "Alertmanager"
description: "Customize Alertmanager alert handling"
weight: 2
draft: false
aliases:
- /docs/customize/alertmanager
- /docs/observability/monitoring/configure/alertmanager
---
Alertmanager sends alerts that are firing in Prometheus to configured receivers.
PrometheusRules will trigger alerts based on the value of metrics.
Alertmanager groups, routes, and silences these alerts according to its configuration.
Alertmanager provides receiver integrations for email, Slack, PagerDuty, and other popular notification services.

## Enable Alertmanager

First, enable Alertmanager by configuring it in the Prometheus Operator component
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

Next, create an AlertmanagerConfig to configure the receivers to which Alertmanager will send alerts.
To create the AlertmanagerConfig, access the Verrazzano console and navigate to the following location:

**Monitoring** > **Alerting** > **AlertmanagerConfigs**

Alertmanager will automatically discover AlertmanagerConfigs in the same namespace where it is deployed,
which is `verrazzano-monitoring`, by default.

For more information about Alertmanager configurations, see the [Alertmanager Documentation](https://prometheus.io/docs/alerting/latest/configuration/).

## Deploy a PrometheusRule

After you have enabled Alertmanager and configured an AlertmanagerConfig with a receiver and route,
you can deploy rules that trigger alerts.
To create a `TestAlertRule`, run the following command.
This PrometheusRule will send an alert if the last configuration reload in the Prometheus pod was unsuccessful.
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

You can configure additional alerts by creating your own PrometheusRules. By default, Verrazzano configures several alerting rules,
which can be viewed in the Thanos Ruler console. For more information, see
[Alerting with Thanos Ruler]({{< relref "/docs/observability/monitoring/configure/thanos#alerting-with-thanos-ruler" >}}).

For more information, see [Deploying Prometheus Rules](https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/user-guides/alerting.md#deploying-prometheus-rules).
