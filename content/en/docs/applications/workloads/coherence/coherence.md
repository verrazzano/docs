---
title: "Coherence Workload"
linkTitle: "Coherence"
description: "Using a Coherence Workload in an application"
weight: 4
draft: true
---

## Overview
A Verrazzano application can contain any number of Coherence component workloads, where each workload
is a standalone Coherence cluster, independent from any other Coherence cluster in the application.  
Verrazzano uses the standard Coherence operator to provision and manage clusters as documented 
at [Coherence Operator](https://oracle.github.io/coherence-operator/docs/latest).  The Coherence operator
uses a CRD, coherence.oracle.com (Coherence resource), to represent a Coherence cluster.  When a Verrazzano
application with Coherence is provisioned, Verrazzano will automatically configure the default logging and 
metrics for the Coherence cluster.  Logs will be shipped to ElasticSeach and metrics to Prometheus.  
This telemetry data can be viewed using Kibana and Grafana consoles.

## OAM Component
The custom resource YAML for the Coherence cluster is specified as a `VerrazzanoCoherenceWorkload` custom resource. In the 
example below, everything under the `spec:` section is standard Coherence resource YAML that you would normally use
to provision a Coherence cluster.
```
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: orders
  namespace: sockshop
spec:
  workload:
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: VerrazzanoCoherenceWorkload
    spec:
      template:
        metadata:
          name: orders-coh
        spec:
          cluster: SockShop
          ...
```

### Lifecycle
With Verrazzano, you manage the lifecycle of applications using Componand and ApplicationConfiguration resources.
Normally, you would modify the Cluster resource to make changed or to do lifecycle operations like scale-in and scale-out.  
However, in the Verrazzano enviroment, the Cluster resource is owned by Verrazzano and will be reconciled 
to match the component workload spec.  Therefore, you need to managed the cluster configuration by modifying
the component workload resource.  Verrazzano will notice that the component resource change and will then update
the Coherence resource as needed.

#### Provisioning
When you apply the component YAML above, Kubernetes will create a `component.oam.verrazzano.io` resource, but 
the Coherence cluster will not be created until you create the ApplicationConfiguration resource, which references
the Coherence component.  When the application is created, Verrazzano creates a Coherence resource for each cluster,
which is subsequently processed by the Coherence operator, resulting in a new cluster.  Once a cluster is created,
the Coherence operator will watch the Coherence resource to reconcile the state of the cluster.  
You can add a new Coherence workload to a running application, or remove an existing workload, simply be modifying
the ApplicationConfiguration resource and adding or removing the Coherence component. 

#### Scaling
Scaling a Coherence cluster is easily done by modifying the replicas field in the component resource.  Verrazzano
will modify the Coherence resource replicas field and the cluster will be scaled accordingly.
```
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: orders
  namespace: sockshop
spec:
  workload:
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: VerrazzanoCoherenceWorkload
    spec:
      template:
        metadata:
          name: orders-coh
        spec:
          cluster: SockShop
          replicas: 3
          ...
```

**NOTE:** A Coherence cluster provisioned with Verrazzano does not support autoscaling with a Horizontal Pod Autoscaler.

#### Termination
You can terminate the Coherence cluster by removing the component it from the ApplicationConfiguration or by
deleting the ApplicationConfiguration resource.

{{< alert title="NOTE" color="warning" >}}
Do not delete the Coherence component if the application is still using it. 
{{< /alert >}}


## Logging
When a Coherence cluster is provisioned, Verrazzano automatically configures it to send logs to Elasticsearch.  This is done by
injecting Fluentd sidecar configuration into the Coherence resource. The Coherence operator will then create the pod with the
Fluentd sidecar.  The sidecar periodically copies the Coherence logs from /logs to stdout, enabling the Fluend daemonset 
in the `verrazzano-system` namespace to ship the logs to Elasticsearch.  Note that the Fluend sidecar running in the Coherence
pod never communicates with Elasticsearch or any other network endpoint.

The logs are placed in a per-namespace index named `verrazzano-namespace-<namespace>`, for example: `verrazzano-namespace-sockshop`.
All logs from Coherence pods in the same namespace will go into the same index, even for different applications.  
This is standard behavior and there is no way to disable or change it.

Each log record has some Coherence and application fields, along with the log message itself.  For example:
```
 kubernetes.labels.coherenceCluster        SockShop
 kubernetes.labels.app_oam_dev/name        sockshop-appconf
 kubernetes.labels.app_oam_dev/component   orders
 ...
```

## Metrics
Verrazzano uses Prometheus to scrape metrics from Coherence cluster pods.  Like logging, metrics scraping is also automatically
enabled during provisioning, however the Coherence resource YAML must have proper metrics configuration.  For details see 
[Coherence Metrics](https://oracle.github.io/coherence-operator/docs/latest/#/metrics/020_metrics).  The short summary is that
there are two different ways to configure the Coherence metrics endpoint.  If your application serves metrics from an endpoint, for
example a Helidon application, then you do not use the native Coherence metrics endpoint, otherwise you do.  To see the difference,
lets examine the `socks-shop` and `bobs-books` examples.

### Bobs Books
The [bobs-books](https://github.com/verrazzano/verrazzano/blob/master/examples/bobs-books) example uses the default 
Coherence metrics endpoint, so the configuration must enable this feature as shown below by the metrics section of the 
`roberts-coherence` component in the YAML in [bobs-books-comp.yaml](https://github.com/verrazzano/verrazzano/blob/master/examples/bobs-books/bobs-books-comp.yaml).
```          ...
          coherence:
            metrics:
              enabled: true
```

### Socks Shop
The [sock-shop](https://github.com/verrazzano/verrazzano/blob/master/examples/sock-shop) example, which is a helidon application with embedded Coherence, explicitly specifies
the metrics port, but doesn't enable Coherence metrics.
```
          ports:
            ...
            - name: metrics
              port: 7001
              serviceMonitor:
                enabled: true
```

Because `sock-shop` components are  not using the default Coherence metrics port, you must add a `MetricsTrait` section to the ApplicationConfiguration for each component
specifying the listening port as follows:

```
        - trait:
            apiVersion: oam.verrazzano.io/v1alpha1
            kind: MetricsTrait
            metadata:
              name: carts-metrics
            spec:
              port: 7001
```

### Prometheus configuration and pod annotations
Prometheus is configured to scrape targets using the configmaps in `verrazzano-system` namespace.  During applications deployment, 
Verrazzano updates the `vmi-system-prometheus-config` configmap and adds targets for the application pods.  Verrazzano also annotates
those pods to match the expected annotations in the configmap.  

Here is an example of sockshop Prometheus configmap section for catalog.  Notice that pods in the `sockshop` namespace with labels `app_oam_dev_name`
and `app_oam_dev_component` are targeted and that the annotations `verrazzano_io/metricsEnabled`, `verrazzano_io/metricsPath` and  
`verrazzano_io/metricsPort` are expected.
```
- job_name: sockshop-appconf_default_sockshop_catalog
  ...
  kubernetes_sd_configs:
  - role: pod
    namespaces:
      names:
      - sockshop
  relabel_configs:
  - source_labels: [__meta_kubernetes_pod_annotation_verrazzano_io_metricsEnabled,
      __meta_kubernetes_pod_label_app_oam_dev_name, __meta_kubernetes_pod_label_app_oam_dev_component]
  ...  
  - source_labels: [__meta_kubernetes_pod_annotation_verrazzano_io_metricsPath]
  ...
  - source_labels: [__address__, __meta_kubernetes_pod_annotation_verrazzano_io_metricsPort]
```

Here is the corresponding catalog pod annotations.  
```
kind: Pod
metadata:
  labels:
    ...
    app.oam.dev/component: catalog
    app.oam.dev/name: sockshop-appconf
  annotations:
    ...
    verrazzano.io/metricsEnabled: "true"
    verrazzano.io/metricsPath: /metrics
    verrazzano.io/metricsPort: "7001"
```

## Scaling

## Istio Integration




