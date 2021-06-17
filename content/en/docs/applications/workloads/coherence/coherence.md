---
title: "Coherence Workload"
linkTitle: "Coherence"
description: "Using a Coherence workload in an application"
weight: 4
draft: true
---

## Overview
A Verrazzano application can contain any number of Coherence component workloads, where each workload
is a standalone Coherence cluster, independent from any other Coherence cluster in the application.  
Verrazzano uses the standard Coherence operator to provision and manage clusters as documented
at [Coherence Operator](https://oracle.github.io/coherence-operator/docs/latest).  The Coherence operator
uses a CRD, coherence.oracle.com (Coherence resource), to represent a Coherence cluster.  When a Verrazzano
application with Coherence is provisioned, Verrazzano will configure the default logging and
metrics for the Coherence cluster.  Logs will be sent to Elasticsearch and metrics to Prometheus.  
You can view this telemetry data using Kibana and Grafana consoles.

## OAM component
The custom resource YAML file for the Coherence cluster is specified as a VerrazzanoCoherenceWorkload custom resource.
In the following example, everything under the `spec:` section is standard Coherence resource YAML that you would typically use
to provision a Coherence cluster.  Including this component reference in your ApplicationConfiguration will result
in a new Coherence cluster being provisioned.  You can have multiple clusters in the same application with no conflict.
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

### Life cycle
With Verrazzano, you manage the lifecycle of applications using Component and ApplicationConfiguration resources.
Typically, you would modify the Coherence cluster resource to make changes or to do lifecycle operations,
like scale in and scale out.  However, in the Verrazzano environment, the Cluster resource is owned by the
Verrazzano application operator and will be reconciled to match the component workload resource.  Therefore,
you need to manage the cluster configuration by modifying the resource, either by `kubectl edit` or applying a new YAML file.  
Verrazzano will notice that the component resource changed and will update the Coherence resource as needed.

#### Provisioning
When you apply the component YAML  file shown previously, Kubernetes will create a component.oam.verrazzano.io resource, but
the Coherence cluster will not be created until you create the ApplicationConfiguration resource, which references
the Coherence component.  When the application is created, Verrazzano creates a Coherence custom resource for each
cluster, which is subsequently processed by the Coherence operator, resulting in a new cluster.  After a cluster
is created, the Coherence operator will monitor the Coherence resource to reconcile the state of the cluster.  
You can add a new Coherence workload to a running application, or remove an existing workload, simply be modifying
the ApplicationConfiguration resource and adding or removing the Coherence component.

#### Scaling
Scaling a Coherence cluster is easily done by modifying the replicas field in the component resource.  Verrazzano
will modify the Coherence resource replicas field and the cluster will be scaled accordingly.  The following example
configuration shows the `replicas` field that specifies the number of pods in the cluster.
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
You can terminate the Coherence cluster by removing the component from the ApplicationConfiguration or by
deleting the ApplicationConfiguration resource entirely.

{{< alert title="NOTE" color="warning" >}}
Do not delete the Coherence component if the application is still using it.
{{< /alert >}}


## Logging
When a Coherence cluster is provisioned, Verrazzano configures it to send logs to Elasticsearch.  This is done by
injecting Fluentd sidecar configuration into the Coherence resource. The Coherence operator will create the pod with the
Fluentd sidecar.  This sidecar periodically copies the Coherence logs from `/logs` to stdout, enabling the Fluentd DaemonSet
in the `verrazzano-system` namespace to send the logs to Elasticsearch.  Note that the Fluend sidecar running in the Coherence
pod never communicates with Elasticsearch or any other network endpoint.

The logs are placed in a per-namespace Elasticsearch index named `verrazzano-namespace-<namespace>`,
for example: `verrazzano-namespace-sockshop`.  All logs from Coherence pods in the same namespace will
go into the same index, even for different applications.  This is standard behavior and there is no way to disable or change it.

Each log record has some Coherence and application fields, along with the log message itself.  For example:
```
 kubernetes.labels.coherenceCluster        SockShop
 kubernetes.labels.app_oam_dev/name        sockshop-appconf
 kubernetes.labels.app_oam_dev/component   orders
 ...
```

## Metrics
Verrazzano uses Prometheus to scrape metrics from Coherence cluster pods.  Like logging, metrics scraping is also
enabled during provisioning, however, the Coherence resource YAML file must have proper metrics configuration.  For details see
[Coherence Metrics](https://oracle.github.io/coherence-operator/docs/latest/#/metrics/020_metrics).  In summary,
there are two different ways to configure the Coherence metrics endpoint.  Coherence has a default metrics endpoint that you can
enable.  If your application serves metrics from its own endpoint, such as a Helidon application, then do not use the native
Coherence metrics endpoint.  To see the difference, examine the `socks-shop` and `bobs-books` examples.

### Bobs Books
The [bobs-books](https://github.com/verrazzano/verrazzano/blob/master/examples/bobs-books) example uses the default
Coherence metrics endpoint, so the configuration must enable this feature, shown in the following metrics section of the
`roberts-coherence` component in the YAML file, [bobs-books-comp.yaml](https://github.com/verrazzano/verrazzano/blob/master/examples/bobs-books/bobs-books-comp.yaml).
```          ...
          coherence:
            metrics:
              enabled: true
```

### Sock Shop
The [sock-shop](https://github.com/verrazzano/verrazzano/blob/master/examples/sock-shop) example, which is a Helidon
application with embedded Coherence, explicitly specifies the metrics port 7001 and doesn't enable Coherence metrics.  Coherence
metrics will still be scraped, but not at the default endpoint.
```
          ports:
            ...
            - name: metrics
              port: 7001
              serviceMonitor:
                enabled: true
```

Because `sock-shop` components are  not using the default Coherence metrics port, you must add a MetricsTrait section
to the ApplicationConfiguration for each component, specifying the metrics port as follows:
```
        - trait:
            apiVersion: oam.verrazzano.io/v1alpha1
            kind: MetricsTrait
            metadata:
              name: carts-metrics
            spec:
              port: 7001
```

### Prometheus configuration
Prometheus is configured to scrape targets using the ConfigMaps in the `verrazzano-system` namespace.  During applications deployment,
Verrazzano updates the `vmi-system-prometheus-config` ConfigMap and adds targets for the application pods.  Verrazzano also annotates
those pods to match the expected annotations in the ConfigMap. When the application is deleted, Verrazzano removes the targets from
the ConfigMap.  You do not need to manually modify the ConfigMap or annotate the application pods.

Here is an example of the`sock-shop` Prometheus ConfigMap section for catalog.  Notice that pods in the `sock-shop` namespace with labels `app_oam_dev_name`
and `app_oam_dev_component` are targeted.  Prometheus will find those pods then look at the pod annotations `verrazzano_io/metricsEnabled`, `verrazzano_io/metricsPath`
and  `verrazzano_io/metricsPort` for scrape configuration.
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

Here is the corresponding catalog pod labels and annotations.  
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

## Istio Integration
Verrazzano ensures that Coherence clusters are not included in an Istio mesh, even if the namespace has the `istio-injection: enabled` label.
This is done by adding the `sidecar.istio.io/inject: "false"` annotation to the Coherence resource, resulting in Coherence pods being
created with that label.  However, other application components in the mesh using mTLS may need to communicate with Coherence.  To handle this case,
Verrazzano automatically creates an Istio DestinationRule to disable TLS for the Coherence port.  This policy disables mTLS for port
9000, which happens to be used as a Coherence `extend` port for Bob's books.
```
  trafficPolicy:
    portLevelSettings:
    - port:
        number: 9000
      tls: {}
   ...
```

Currently, port 9000 is the only port where TLS is disabled, so you need to use this as the Coherence `extend` port if
other components in the mesh access Coherence over the `extend` protocol.

## Summary
Verrazzano makes it easy to deploy and observe Coherence clusters in your application, providing seamless integration with other
components in your application running in an Istio mesh.
