---
title: "Metrics"
linkTitle: Metrics
description: "Understand Verrazzano metrics gathering and viewing"
weight: 9
draft: false
---


The Verrazzano metrics stack automates metrics aggregation and consists of Prometheus and Grafana components.
Metrics sources expose system and application metrics.
The Prometheus components retrieve and store the metrics and Grafana provides dashboards to
visualize them.

![Metrics](/docs/images/metrics.png)

## Metrics sources

### OAM

Metrics sources produce metrics and expose them to the Kubernetes Prometheus system using annotations in the pods.
The metrics annotations may differ slightly depending on the resource type.
The following is an example of the WebLogic Prometheus-related configuration specified in the `todo-list` application pod:

`$ kubectl describe pod tododomain-adminserver -n todo-list`

```
Annotations:  prometheus.io/path: /wls-exporter/metrics
              prometheus.io/port: 7001
              prometheus.io/scrape: true
```

For other resource types, such as Coherence or Helidon, the annotations would look similar to this:

```
Annotations:  verrazzano.io/metricsEnabled: true
              verrazzano.io/metricsPath: /metrics
              verrazzano.io/metricsPort: 8080
```

To look directly at the metrics that are being made available by the metric source, map the port and then access the path.

For example, for the previous metric source:

- Map the port being used to expose the metrics.
  ```
  $ kubectl port-forward tododomain-adminserver 7001:7001 -n todo-list
  ```

- Get the user name and password used to access the metrics source from the corresponding secret.

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

- Access the metrics at the exported path, using the user name and password retrieved in the previous step.
   ```
   $ curl -u USERNAME:PASSWORD localhost:7001/wls-exporter/metrics
   ```
  
### Default Kubernetes workloads

Verrazzano enables metric sources for Kubernetes workloads deployed without OAM components. 
Currently, Verrazzano supports the following workload types: Deployments, ReplicaSets, StatefulSets, and Pods.
To enable metrics for Kubernetes workloads, you must label the workload namespace with `verrazzano-managed=true`.

#### Metrics Template

A [Metrics Template]({{< relref "/docs/reference/api/Verrazzano/metricstemplate.md" >}}) is a custom resource created by Verrazzano to manage metrics configurations for default Kubernetes workloads.
Metrics templates can be placed in the workload namespace or the `verrazzano-system` namespace.
By default, Verrazzano installs a metrics template named `standard-k8s-metrics-template` in the `verrazzano-system` namespace.
This metrics templates handles all aforementioned workload types.
You can create your own metrics templates to extend and alter the functionality of the metrics template
if the default metrics template does not meet your requirements.

As outlined in the [API]({{< relref "/docs/reference/api/Verrazzano/metricstemplate.md" >}}), the metrics template contains a `workloadSelector` field that specifies the resources for which the template applies.
If you want to forgo the workload selection and manually specify a template, you can optionally add the annotation `app.verrazzano.io/metrics=<template-name>`
to the namespace of the workload or the workload itself.
Additionally, you can opt out of metrics for your namespace or workload by setting the annotation `app.verrazzano.io/metrics=none`.

The precedence of template matching is as follows:

1. A workload selects a template in the workload namespace through an annotation.
2. A workload selects a template in the `verrazzano-system` namespace through an annotation.
3. The workload namespace selects a template in the workload namespace through an annotation.
4. The workload namespace selects a template in the `verrazzano-system` namespace through an annotation.
5. A template in the workload namespace matches the workload through the `workloadSelector` field.
6. A template in the `verrazzano-system` namespace matches the workload through the `workloadSelector` field.

To verify that the metrics template process was successful, look for a Prometheus target with this formatting:
`<workload-namespace>_<workload-name>_<workload-type>`

#### Prometheus overrides

The `standard-k8s-metrics-template` metrics template installed by Verrazzano uses the following pod annotations to populate the Prometheus configuration.
If not specified, Verrazzano will use these default values:

```
Annotations:  prometheus.io/path: /metrics
              prometheus.io/port: 8080
              prometheus.io/scrape: true
```

To alter these values, annotate the workload pod with the corresponding annotation.
For example, if you want to change the metrics path, you could add the following to a Deployment definition:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hello-helidon-deployment
  namespace: hello-helidon
  annotations:
    app.verrazzano.io/metrics: standard-k8s-metrics-template
spec:
  template:
    metadata:
      # add path annotation to the pod template
      annotations:
        prometheus.io/path: "/custom/metrics/path"
```

#### Prometheus configuration
If you want to create your own Metrics Template, you will need to construct a [Prometheus scrape config](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#scrape_config).
The scrape config uses [Go Templates](https://pkg.go.dev/text/template) to generate config values based on kubernetes resources.
You are able to reference values in the workload and namespace definitions for use in the scrape config.
Do not include the `job_name` field in your scrape config as it will be generated by Verrazzano.
You can reference the default scrape config in the [Metrics Template API]({{< relref "/docs/reference/api/Verrazzano/metricstemplate.md" >}}) for guidance on how to construct a Prometheus scrape config.

### Metrics server

- Single pod per cluster.
- Named `vmi-system-prometheus-*` in `verrazzano-system` namespace.
- Discovers exposed metrics source endpoints.
- Scrapes metrics from metrics sources.
- Responsible for exposing all metrics.

## Grafana

Grafana provides visualization for your Prometheus metric data.

- Single pod per cluster.
- Named `vmi-system-grafana-*` in `verrazzano-system` namespace.
- Provides dashboards for metrics visualization.

To access Grafana:

- Get the hostname from the Grafana ingress.
   ```
   $ kubectl get ingress vmi-system-grafana -n verrazzano-system

   # Sample output
   NAME                 CLASS    HOSTS                                              ADDRESS          PORTS     AGE
   vmi-system-grafana   <none>   grafana.vmi.system.default.123.456.789.10.nip.io   123.456.789.10   80, 443   26h
   ```

- Get the password for the user `verrazzano`.
   ```
   $ kubectl get secret \
       --namespace verrazzano-system verrazzano \
       -o jsonpath={.data.password} | base64 \
       --decode; echo
   ```
- Access Grafana in a browser using the previous hostname.
- Log in using the `verrazzano` user and the previous password.

![Grafana](/docs/images/grafana-initial-page.png)


From here, you can select an existing dashboard or create a new dashboard.
To select an existing dashboard, use the drop-down list in the top left corner.
The initial value of this list is `Home`.


To view host level metrics, select `Host Metrics`. This will provide system metrics for all
of the nodes in your cluster.


To view the application metrics for the `todo-list` example application, select `WebLogic Server Dashboard`
because the `todo-list` application is a WebLogic application.

![WebLogicDashboard](/docs/images/grafana-weblogic-dashboard.png)
