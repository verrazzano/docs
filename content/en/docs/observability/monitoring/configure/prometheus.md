---
title: "Prometheus"
description: "Customize Prometheus to monitor Verrazzano"
weight: 2
draft: false
aliases:
  - /docs/customize/prometheus
  - /docs/observability/monitoring/configure/prometheus
---
Prometheus is a system for monitoring cloud native applications and is used by Verrazzano to monitor applications. Prometheus is used in Verrazzano to collect system performance metrics and metrics for applications deployed or managed by Verrazzano. Prometheus analyzes the metrics and provides visualization using Grafana.

## Customize Prometheus configuration

Verrazzano installs Prometheus components, including Prometheus Operator and Prometheus, using the
[kube-prometheus-stack]({{% release_source_url path=platform-operator/thirdparty/charts/prometheus-community/kube-prometheus-stack %}}) Helm chart.
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

For more information about setting component overrides, see [Installation Overrides]({{< relref "docs/setup/installationOverrides.md " >}}).

For information about all the overrides supported by the kube-prometheus-stack chart in Verrazzano, see [values.yaml](https://github.com/verrazzano/verrazzano/blob/master/platform-operator/thirdparty/charts/prometheus-community/kube-prometheus-stack/values.yaml).

For instructions to customize persistent storage settings for Prometheus, see [Customize Persistent Storage]({{< relref "docs/observability/logging/configure-opensearch/storage.md " >}}).

## Configure Alertmanager

You can configure Alertmanager to send alerts about problems occurring in the cluster. 
Alertmanager provides integrations for email, Slack, PagerDuty,
and other popular notification services to receive alerts.

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

Next, create an AlertmanagerConfig to configure the receivers that Alertmanager will send alerts to. 
To create the AlertmanagerConfig, access the Verrazzano console 
and navigate to **Monitoring** > **Alerting** > **AlertmanagerConfigs**.
Alertmanager will automatically discover AlertmanagerConfigs in the same namespace,
which by default in Verrazzano is `verrazzano-monitoring`. If you would prefer to create the AlertmanagerConfig
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
