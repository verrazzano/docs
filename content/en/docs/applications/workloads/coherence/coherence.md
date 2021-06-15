---
title: "Coherence Workload"
linkTitle: "Coherence Workload"
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
this component.  When the application is created, Verrazzano creates a Coherence resource for each cluster,
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
in the `verrazzano-system` namespace to ship the logs to Elasticsearch.  

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

## Scaling

## Istio Integration




