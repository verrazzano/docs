---
title: "Metrics"
linkTitle: Metrics
description: "Understand Verrazzano metrics gathering and viewing"
weight: 2
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
For details on Service Monitor and Pod Monitor, refer to the [Prometheus Operator documentation](https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/user-guides/getting-started.md).

When creating the Service Monitor or Pod Monitor for your workload, include the label `release`, with the value
`prometheus-operator` on the monitor resource.

#### Verify metrics collection

To verify that the metrics are being collected for your workload, follow these steps.
1. Access the [Prometheus console]({{< relref "/docs/access/_index.md" >}}).
2. From the console, use the navigation bar to access Status/Targets.
3. On this page, you will see a target name with this formatting: `<monitor-type>/<workload-namespace>_<workload-name>_<workload-type>`, where `monitor-type` may be serviceMonitor or podMonitor.
4. Copy this job name from the target labels for use in future queries.
5. Verify that the State of this target is `UP`.
6. Next, use the navigation bar to access the Graph.
7. Here, use the job name you copied to construct this expression: `{job="<job_name>"}`
8. Use the graph to run this expression and verify that you see application metrics appear.

Metrics Traits use Service Monitors which require [Services](https://kubernetes.io/docs/concepts/services-networking/service/) for metrics collection.
If you are unable to verify metrics collection, you might need to manually create a Service for the workload.

For more information on Prometheus solutions, see [Troubleshooting Prometheus]({{< relref "/docs/troubleshooting/troubleshooting-prometheus.md" >}}).

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

## Grafana

Grafana provides visualization for your Prometheus metric data.

- Single pod per cluster.
- Named `vmi-system-grafana-*` in the `verrazzano-system` namespace.
- Provides dashboards for metrics visualization.

To access Grafana:

1. Get the host name from the Grafana ingress.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl get ingress vmi-system-grafana -n verrazzano-system

   # Sample output
   NAME                 CLASS    HOSTS                                              ADDRESS          PORTS     AGE
   vmi-system-grafana   <none>   grafana.vmi.system.default.123.456.789.10.nip.io   123.456.789.10   80, 443   26h
   ```

</div>
{{< /clipboard >}}


1. Get the password for the user `verrazzano`.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl get secret \
       --namespace verrazzano-system verrazzano \
       -o jsonpath={.data.password} | base64 \
       --decode; echo
   ```

</div>
{{< /clipboard >}}

1. Access Grafana in a browser using the host name.
1. Log in using the `verrazzano` user and the password.

![Grafana](/docs/images/grafana-initial-page.png)

### Grafana dashboards

Verrazzano installs a number of preconfigured dashboards in Grafana. These dashboards are organized logically into folders. To view the folders, locate the **Dashboards** icon and select **Manage**.

![GrafanaFolders](/docs/images/grafana-manage-folders.png)

Within each folder, you will find one or more preconfigured dashboards. The dashboards provide a visual representation of metrics for monitoring your applications, the Kubernetes clusters where your applications are running, and Verrazzano itself. You can add to these dashboards, and you can copy and modify the preconfigured dashboards.

Here are the folders and dashboard descriptions:

- `Coherence` - A set of dashboards for monitoring Coherence applications. They provide metrics from Coherence clusters, Caches, Elastic Data, Federation Details, HTTP Servers, Kubernetes, Machines, Cluster Members, Persistence Summary, Proxy Servers, and Coherence Services.
- `Helidon` - For Helidon workloads, provides the JVM details for Helidon applications, such as Status, Heap Usage, JVM Heap Sizes, Thread Count, HTTP Requests, and such.
- `Istio` - A set of dashboards for monitoring the Verrazzano Istio service mesh and the workloads running in the mesh.
- `JVM` -  For monitoring applications deployed in Verrazzano.
- `NGINX` - For monitoring the Verrazzano system ingress controller and the ingresses created using the ingress controller. Metrics include Controller Request Volume, Controller Connections, Controller Success Rate, Config Reloads, Network Pressure, and such.
- `OpenSearch` - Provides metrics from OpenSearch clusters, such as Cluster Health, Shard Details, Index Details, JVM Metrics, and such.
- `Prometheus Operator` - Provides metrics for the cluster compute resources, such as CPU Utilization, Memory Limits, and such.
- `WebLogic` - For WebLogic workloads, provides WebLogic Server runtime metrics to monitor and diagnose the runtime deployment of WebLogic Server.

In addition, there are the following preconfigured Grafana Verrazzano dashboards. These dashboards are located in `Verrazzano Application`, `Verrazzano Monitoring`, and `Verrazzano System` folders:

- `Verrazzano Application` contains the `Application Status` dashboard. This dashboard provides information on the overall health and performance of OAM applications that are deployed in Verrazzano and the details of the running pods. You can filter this information based on cluster, application, and component.
   - When you deploy a new application in Verrazzano, the application is automatically added to the dashboard and becomes available in the list of `Applications`. You can select the specific application that you want to monitor and select which application metrics to view. Metrics are available in three rows:  
      - `Summary` provides CPU and memory usage and pod status.
      - `Storage` provides disk and PVC (Persistent Volume Claims) usage.
      - `Requests` provides HTTP requests and request metrics.
- `Verrazzano Monitoring` contains dashboards for monitoring the Kubernetes clusters where Verrazzano is running:
    - `alertmanager-mixin` displays alerts created by Alertmanager, including the successful and invalid notifications sent by Alertmanager.
    - `etcd-mixin` provides cluster metrics and shows additional information, such as active streams, RPC rate, database size, memory usage, client traffic, peer traffic, and such.
    - `kubernetes-mixin` provides CPU, memory and network metrics based on cluster, pod, workload type, and nodes; network bandwidth based on cluster, pod, workload type, and nodes; persistent volume usage; and metrics for proxy and scheduler.
    - `node-exporter-mixin` provides node level status for CPU, memory, disk, and network usage.

![Verrazzano Monitoring Dashboard](/docs/images/grafana-verrazzano-monitoring-dashboards.png)

- `Verrazzano System` has a set of dashboards  that provide information on the health of all Verrazzano system components and the resource usage of Kubernetes resources across clusters.
    - `Resource Usage Detailed` gives a detailed view of the resource usage for each of the Verrazzano system components, such as the application operator, cluster operator, monitoring operator, and platform operator. You can filter information based on cluster, component, and so on.
    - `Resource Usage Summary` gives a summary of the resource usage that can be viewed for all components or for a specific component. You can filter information based on cluster, component, and so on. Metrics are available in three rows:  
       - `Summary` provides CPU and memory usage and pod status.
       - `Storage` provides disk and PVC (Persistent Volume Claims) usage.
       - `Requests` provides HTTP requests and request metrics.
    - `System Health` gives the health for all Verrazzano system components that can be viewed for local clusters or any other registered clusters.

### Dynamic dashboard discovery and portability

Verrazzano can dynamically deploy Grafana dashboards that are configured in a ConfigMap, in the Verrazzano Grafana instance. You can create individual ConfigMaps in your Kubernetes clusters or package the dashboard ConfigMaps with your application. The ConfigMaps automatically add the dashboard JSON to the cluster. The JSON configuration is then translated into a Grafana dashboard and can be viewed in the Grafana console.

You can use dashboard ConfigMaps to deploy custom dashboards without accessing the Grafana console. You cannot modify and save these dashboard ConfigMaps in the Grafana console; if you modify the dashboard, then you must save it as a new dashboard. You create the ConfigMap in the _admin_ cluster.

To configure a dashboard as a ConfigMap:

1. Create a dashboard as a JSON file. Or, you can export an existing Grafana dashboard as a JSON file.
2. Create a ConfigMap file as follows:

   - The `grafana_dashboard` label must be set to `"1"` so that Grafana selects this ConfigMap as a data source for a dashboard. **NOTE**: Use this label _only_ for the `grafana_dashboard`.

   - Name of the JSON file that contains the dashboard JSON.

   - Name of the `k8s-sidecar-target-directory` as `MyDashboardFolder` to place the dashboard in a custom folder in Grafana.



Here is an example dashboard ConfigMap.

```
apiVersion: v1
kind: ConfigMap
metadata:
  annotations:
    k8s-sidecar-target-directory: My App Dashboards
  labels:
    grafana_dashboard: "1"
  name: app-dashboard
  namespace: app
data:
  app_dashboard.json: |-
    {
      "title": "My App Dashboard",
      "uid": "Q4Bkkx",
      "version": 2,
      "panels": [
        {
          ...
        }
      ...
    }
```
