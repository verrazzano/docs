---
title: "Coherence Workload"
weight: 3
draft: false
aliases:
  - /docs/applications/workloads/coherence/coherence
---


A Verrazzano application can contain any number of Coherence component workloads, where each workload
is a standalone Coherence cluster, independent from other Coherence clusters in the application.

Verrazzano uses the standard Coherence Operator to provision and manage clusters, as documented
at [Coherence Operator](https://oracle.github.io/coherence-operator/docs/latest).  The Coherence Operator
uses a CRD, coherence.oracle.com (Coherence resource), to represent a Coherence cluster.  When a Verrazzano
application with Coherence is provisioned, Verrazzano configures the default logging and
metrics for the Coherence cluster.  Logs are sent to OpenSearch and metrics to Prometheus.
You can view this telemetry data using the OpenSearch Dashboards and Grafana consoles.

## OAM Component
The custom resource YAML file for the Coherence cluster is specified as a VerrazzanoCoherenceWorkload custom resource.
In the following example, everything under the `spec:` section is standard Coherence resource YAML that you would typically use
to provision a Coherence cluster.  Including this Component reference in your ApplicationConfiguration will result
in a new Coherence cluster being provisioned.  You can have multiple clusters in the same application with no conflict.
{{< clipboard >}}
<div class="highlight">

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

</div>
{{< /clipboard >}}

### Life cycle
With Verrazzano, you manage the life cycle of applications using Component and ApplicationConfiguration resources.
Typically, you would modify the Coherence cluster resource to make changes or to do lifecycle operations,
like scale in and scale out.  However, in the Verrazzano environment, the cluster resource is owned by the
Verrazzano application operator and will be reconciled to match the Component workload resource.  Therefore,
you need to manage the cluster configuration by modifying the resource, either by `kubectl edit` or applying a new YAML file. Verrazzano
will notice that the Component resource changed and will update the Coherence resource as needed.

#### Provisioning
When you apply the Component YAML  file shown previously, Kubernetes will create a `component.oam.verrazzano.io` resource, but
the Coherence cluster will not be created until you create the ApplicationConfiguration resource, which references
the Coherence component.  When the application is created, Verrazzano creates a Coherence custom resource for each
cluster, which is subsequently processed by the Coherence Operator, resulting in a new cluster.  After a cluster
is created, the Coherence Operator will monitor the Coherence resource to reconcile the state of the cluster. You can
add a new Coherence workload to a running application, or remove an existing workload, by modifying
the ApplicationConfiguration resource, and adding or removing the Coherence component.

#### Scaling
Scaling a Coherence cluster is done by modifying the replicas field in the Component resource.  Verrazzano
will modify the Coherence resource replicas field and the cluster will be scaled accordingly.  The following example
configuration shows the `replicas` field that specifies the number of pods in the cluster.
{{< clipboard >}}
<div class="highlight">

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

</div>
{{< /clipboard >}}


**NOTE**: A Coherence cluster provisioned with Verrazzano does not support autoscaling with a Horizontal Pod Autoscaler.

#### Termination
You can terminate the Coherence cluster by removing the Component from the ApplicationConfiguration or by
deleting the ApplicationConfiguration resource entirely.

{{< alert title="NOTE" color="danger" >}}
Do not delete the Coherence component if the application is still using it.
{{< /alert >}}


## Logging
When a Coherence cluster is provisioned, Verrazzano configures it to send logs to OpenSearch.  This is done by
injecting a Fluentd sidecar configuration into the Coherence resource. The Coherence Operator will create the pod with the
Fluentd sidecar.  This sidecar periodically copies the Coherence logs from `/logs` to stdout, enabling the Fluentd DaemonSet
in the `verrazzano-system` namespace to send the logs to OpenSearch.  Note that the Fluend sidecar running in the Coherence
pod never communicates with OpenSearch or any other network endpoint.

The logs are placed in a per-namespace OpenSearch data stream named `verrazzano-application-<namespace>`,
for example: `verrazzano-application-sockshop`.  All logs from Coherence pods in the same namespace will
go into the same data stream, even for different applications.  This is standard behavior and there is no way to disable or change it.

Each log record has some Coherence and application fields, along with the log message itself.  For example:
{{< clipboard >}}
<div class="highlight">

     kubernetes.labels.coherenceCluster        SockShop
     kubernetes.labels.app_oam_dev/name        sockshop-appconf
     kubernetes.labels.app_oam_dev/component   orders
     ...

</div>
{{< /clipboard >}}

## Metrics
Verrazzano uses Prometheus to scrape metrics from Coherence cluster pods.  Like logging, metrics scraping is also
enabled during provisioning, however, the Coherence resource YAML file must have proper metrics configuration.  For details, see
[Coherence Metrics](https://oracle.github.io/coherence-operator/docs/latest/#/metrics/020_metrics).  In summary,
there are two ways to configure the Coherence metrics endpoint.  Coherence has a default metrics endpoint that you can
enable.  If your application serves metrics from its own endpoint, such as a Helidon application, then do not use the native
Coherence metrics endpoint.  To see the difference, examine the `socks-shop` and `bobs-books` examples.

### Bobs Books
The [bobs-books]( {{< release_source_url path=examples/bobs-books >}} ) example uses the default
Coherence metrics endpoint, so the configuration must enable this feature, shown in the following metrics section of the
`roberts-coherence` component in the YAML file, [bobs-books-comp.yaml]( {{< release_source_url path=examples/bobs-books/bobs-books-comp.yaml >}} ).
{{< clipboard >}}
<div class="highlight">

    ...
              coherence:
                metrics:
                  enabled: true

</div>
{{< /clipboard >}}

### Sock Shop
The [sock-shop]( {{< release_source_url path=examples/sock-shop >}} ) example, which is a Helidon
application with embedded Coherence, explicitly specifies the metrics port 7001 and doesn't enable Coherence metrics.  Coherence
metrics still will be scraped, but not at the default endpoint.
{{< clipboard >}}
<div class="highlight">

          ports:
            ...
            - name: metrics
              port: 7001
              serviceMonitor:
                enabled: true

</div>
{{< /clipboard >}}

Because `sock-shop` components are  not using the default Coherence metrics port, you must add a MetricsTrait section
to the ApplicationConfiguration for each component, specifying the metrics port as follows:
{{< clipboard >}}
<div class="highlight">

        - trait:
            apiVersion: oam.verrazzano.io/v1alpha1
            kind: MetricsTrait
            metadata:
              name: carts-metrics
            spec:
              port: 7001

</div>
{{< /clipboard >}}

### Prometheus configuration
Prometheus is configured using the Prometheus Operator to scrape application targets.  During application deployment,
Verrazzano creates or updates Service Monitors based on the MetricsTrait specified in the ApplicationConfiguration.  When
the application is deleted, Verrazzano removes the Service Monitors so that metrics are no longer collected for it.

Here is an example of the `sock-shop` Prometheus Service Monitor resource for `catalog-coh` in the application namespace.  
Notice that services with certain labels are targeted.  Prometheus Operator will find the Service Monitor and
generate the scrape configuration to be used by Prometheus.
{{< clipboard >}}
<div class="highlight">

    apiVersion: monitoring.coreos.com/v1
    kind: ServiceMonitor
    metadata:
      ....
      name: catalog-coh-metrics
      namespace: sockshop
      ....
    spec:
      endpoints:
      - bearerTokenSecret:
          key: ""
        port: metrics
        relabelings:
        - action: labeldrop
          regex: (endpoint|instance|job|service)
      namespaceSelector: {}
      selector:
        matchLabels:
          coherenceCluster: SockShop
          coherenceComponent: coherence-service
          coherenceDeployment: catalog-coh
          coherencePort: metrics
          coherenceRole: Catalog

</div>
{{< /clipboard >}}

Here are the labels on the corresponding `catalog-coh-metrics` service.  
{{< clipboard >}}
<div class="highlight">

    kind: Service
    metadata:
      labels:
        coherenceCluster: SockShop
        coherenceComponent: coherence-service
        coherenceDeployment: catalog-coh
        coherencePort: metrics
        coherenceRole: Catalog
    spec:
      ports:
      - name: metrics
        port: 9612
        protocol: TCP
        targetPort: 9612
      ....

</div>
{{< /clipboard >}}

## Istio integration
Verrazzano ensures that Coherence clusters are not included in an Istio mesh, even if the namespace has the `istio-injection: enabled` label.
This is done by adding the `sidecar.istio.io/inject: "false"` annotation to the Coherence resource, resulting in Coherence pods being
created with that label.  However, other application components in the mesh using mutual TLS authentication (mTLS)  may need to communicate with Coherence.  To handle this case,
Verrazzano automatically creates an Istio DestinationRule to disable TLS for the Coherence port.  This policy disables mTLS for port
9000, which happens to be used as a Coherence `extend` port for Bob's Books.
{{< clipboard >}}
<div class="highlight">

      trafficPolicy:
        portLevelSettings:
        - port:
            number: 9000
          tls: {}
       ...

</div>
{{< /clipboard >}}

Currently, port 9000 is the only port where TLS is disabled, so you need to use this as the Coherence `extend` port if
other components in the mesh access Coherence over the `extend` protocol.
