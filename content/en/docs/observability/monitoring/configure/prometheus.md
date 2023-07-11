---
title: "Prometheus"
description: "Customize Prometheus to monitor Verrazzano"
weight: 2
draft: false
aliases:
  - /docs/customize/prometheus
---
Prometheus is a system for monitoring cloud native applications and is used by Verrazzano to monitor applications. Prometheus is used in Verrazzano to collect system performance metrics and metrics for applications deployed or managed by Verrazzano. Prometheus analyzes the metrics and provides visualization using Grafana.

## Customize Prometheus configuration

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

For more information about setting component overrides, see [Customizing the Chart Before Installing](https://helm.sh/docs/intro/using_helm/#customizing-the-chart-before-installing).

For instructions to customize persistent storage settings, see [Customize Persistent Storage]({{< relref "docs/observability/logging/configure-opensearch/storage.md " >}}).

## Configure Alertmanager

To configure Alertmanager to send alerts as SMTP notifications, complete the following steps:

1. Create a secret named `smtp-secret` in the `verrazzano-monitoring` namespace which contains the SMTP server credentials. For example:
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl -n verrazzano-monitoring create secret generic smtp-secret \
    --from-literal=username="<smtp server username>" \
    --from-literal=password="<smtp server password>"
   ```

</div>
{{< /clipboard >}}

1. Configure the Prometheus Operator component of the Verrazzano custom resource. For example:
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
                   secrets:
                   - smtp-secret
                 config:
                   global:
                     resolve_timeout: 15m
                     smtp_auth_password_file: /etc/alertmanager/secrets/smtp-secret/password
                     smtp_auth_username: "<smtp server username>"
                     smtp_from: "<e-mail address used when sending out emails>"
                     smtp_smarthost: "<host or host:port for the smtp server>"
                 receivers:
                 - email_configs:
                   - send_resolved: true
                     to: "<e-mail address of the receiver>"
                   name: email-notifications
                 route:
                   group_by:
                   - alertname
                   - datacenter
                   - app
                   receiver: email-notifications
                   routes:
                   - matchers:
                     - alertname =~ "InfoInhibitor|Watchdog"
                     receiver: email-notifications
   ```

</div>
{{< /clipboard >}}

For more information about Alertmanager configurations, see the [Alertmanager Documentation](https://prometheus.io/docs/alerting/latest/configuration/).

After you have enabled Alertmanager, you can deploy alert rules to get proactive alerts.
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

For more information, see [Deploying Prometheus rules](https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/user-guides/alerting.md#deploying-prometheus-rules).

## Configure data retention settings

Verrazzano configures Prometheus with a default data retention setting of 10 days. The rate of metrics data collected depends on many factors, including the number of monitors, the monitor scrape intervals, and the number of metrics returned by each monitor.

When using persistent storage for Prometheus, it is possible to consume all storage. If Prometheus uses all available persistent storage, then queries return no data and new metrics cannot be saved.
You can customize the persistent storage settings, and change the data retention days and configure a maximum retention size. When configuring retention size, a good rule of thumb is to set the value
to no more than 85 percent of the persistent storage size.

The following example configures Prometheus to store at most three days or 40 GB of metrics data.

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
                retention: 3d
                retentionSize: 40GB
```

</div>
{{< /clipboard >}}
