---
title: "Understand Monitoring Components in Verrazzano"
description: "Learn about Verrazzano metrics gathering and viewing"
weight: 1
draft: false
---

The Verrazzano metrics stack automates metrics aggregation and consists of Prometheus and Grafana components.
Metrics sources expose system and application metrics.
The Prometheus components retrieve and store the metrics and Grafana provides dashboards to
visualize them.

![Metrics](/docs/images/metrics.png)

## Metrics sources

The following sections describe metrics sources that Verrazzano provides for OAM and standard Kubernetes applications.

### OAM

Metrics sources produce metrics and expose them to the Kubernetes Prometheus system using annotations in the pods.
The metrics annotations may differ slightly depending on the resource type.
The following is an example of the WebLogic Prometheus-related configuration specified in the `todo-list` application pod:

`$ kubectl describe pod tododomain-adminserver -n todo-list`

{{< clipboard >}}
<div class="highlight">

```
Annotations:  prometheus.io/path: /wls-exporter/metrics
              prometheus.io/port: 7001
              prometheus.io/scrape: true
```

</div>
{{< /clipboard >}}

For other resource types, such as Coherence or Helidon, the annotations would look similar to this:

{{< clipboard >}}
<div class="highlight">

```
Annotations:  verrazzano.io/metricsEnabled: true
              verrazzano.io/metricsPath: /metrics
              verrazzano.io/metricsPort: 8080
```

</div>
{{< /clipboard >}}


To look directly at the metrics that are being made available by the metric source, map the port and then access the path.

For example, for the previous metric source:

- Map the port being used to expose the metrics.
{{< clipboard >}}
<div class="highlight">

  ```
  $ kubectl port-forward tododomain-adminserver 7001:7001 -n todo-list
  ```

</div>
{{< /clipboard >}}


- Get the user name and password used to access the metrics source from the corresponding secret.
{{< clipboard >}}
<div class="highlight">

  ```
  $ kubectl get secret \
      --namespace todo-list tododomain-weblogic-credentials \
      -o jsonpath={.data.username} | base64 \
      --decode; echo
  $ kubectl get secret \
      --namespace todo-list tododomain-weblogic-credentials \
      -o jsonpath={.data.password} | base64 \
      --decode; echo
  ```

</div>
{{< /clipboard >}}

- Access the metrics at the exported path, using the user name and password retrieved in the previous step.
{{< clipboard >}}
<div class="highlight">

   ```
   $ curl -u USERNAME:PASSWORD localhost:7001/wls-exporter/metrics
   ```

</div>
{{< /clipboard >}}

### Standard Kubernetes workloads

Verrazzano supports enabling metric sources for Kubernetes workloads deployed without OAM Components.
To enable metrics for Kubernetes workloads, you must create a Service Monitor or Pod Monitor, as applicable.

Metrics Traits use Service Monitors which require [Services](https://kubernetes.io/docs/concepts/services-networking/service/) for metrics collection.<br>
For details on Service Monitor and Pod Monitor, refer to the [Prometheus Operator documentation](https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/user-guides/getting-started.md).


When creating the Service Monitor or Pod Monitor for your workload, include the label `release`, with the value
`prometheus-operator` on the monitor resource.

#### Verify metrics collection

To verify that the metrics are being collected for your workload, follow these steps.
1. Access the [Prometheus console]({{< relref "/docs/setup/access/_index.md" >}}).
2. From the console, use the navigation bar to access Status/Targets.
3. On this page, you will see a target name with this formatting: `<monitor-type>/<workload-namespace>_<workload-name>_<workload-type>`, where `monitor-type` may be serviceMonitor or podMonitor.
4. Copy this job name from the target labels for use in future queries.
5. Verify that the State of this target is `UP`.
6. Next, use the navigation bar to access the Graph.
7. Here, use the job name you copied to construct this expression: `{job="<job_name>"}`
8. Use the graph to run this expression and verify that you see application metrics appear.

If you are unable to verify metrics collection, you might need to manually create a Service for the workload.

For more information on Prometheus solutions, see [Troubleshooting Prometheus]({{< relref "/docs/observability/monitoring/troubleshooting-prometheus.md" >}}).

#### Legacy workloads

Standard Kubernetes workloads that were metrics sources in earlier versions of Verrazzano (1.3.x or earlier), will continue
to be supported when upgrading to later versions of Verrazzano.

For workloads that used the legacy default metrics template, Verrazzano will create a Service Monitor in the workload's
namespace to ensure that metrics continue to be scraped. You can make any ongoing changes to the metrics source configuration
by editing the Service Monitor.

For workloads that used a legacy custom metrics template, Verrazzano will configure the Prometheus Operator to ensure
that metrics continue to be scraped.

### Metrics server

- Verrazzano installs the Prometheus Operator in the `verrazzano-monitoring` namespace.
- A single Prometheus pod is created by Prometheus Operator in the same namespace.
- Discovers exposed metrics source endpoints.
- Scrapes metrics from metrics sources.
- Responsible for exposing all metrics.
