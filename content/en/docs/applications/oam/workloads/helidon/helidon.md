---
title: "Helidon Workload"
Weight: 4
draft: false
aliases:
  - /docs/applications/workloads/helidon/helidon
---


[Helidon](https://helidon.io) is a collection of Java libraries for writing microservices. Helidon provides an open source,
lightweight, fast, reactive, cloud native framework for developing Java microservices. It is available as two frameworks:

- [Helidon SE](https://helidon.io/docs/latest/#/se/introduction/01_introduction) is a compact toolkit that embraces the
  latest Java SE features: reactive streams, asynchronous and functional programming, and fluent-style APIs.
- [Helidon MP](https://helidon.io/docs/latest/#/mp/introduction/01_introduction) implements and supports Eclipse MicroProfile,
  a baseline platform definition that leverages Java EE and Jakarta EE technologies for microservices and delivers application
  portability across multiple runtimes.

Helidon is designed and built with container-first philosophy.

- Small footprint, low memory usage and faster startup times.
- All 3rd party dependencies are stored separately to enable Docker layering.
- Provides readiness, liveness and customizable health information for container schedulers like [Kubernetes](https://kubernetes.io/).

Containerized Helidon applications are generally deployed as [Deployment](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/deployment-v1/) in Kubernetes.

## Verrazzano integration

Verrazzano supports application definition using [Open Application Model (OAM)](https://oam.dev/). Verrrazzano applications
are composed of [components](https://github.com/oam-dev/spec/blob/master/3.component_model.md) and
[application configurations](https://github.com/oam-dev/spec/blob/master/7.application.md).

Helidon applications are first class citizens in Verrazzano with specialized Helidon workload support, for example,
VerrazzanoHelidonWorkload. VerrazzanoHelidonWorkload is supported as part of `verrazzano-application-operator` in the
Verrazzano installation and no additional operator setup or installation is required. VerrazzanoHelidonWorkload also supports all
the Traits and Scopes defined by Verrazzano along with core ones defined by the OAM specification.

VerrazzanoHelidonWorkload is modeled after [ContainerizedWorkload](https://github.com/oam-dev/spec/blob/v0.2.1/core/workloads/containerized_workload/containerized_workload.md),
for example, it is used for long-running workloads in containers. However, VerrazzanoHelidonWorkload closely resembles and directly refers to
Kubernetes [Deployment](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/deployment-v1/) schema. This
enables an easy lift and shift of existing containerized Helidon applications.

The complete VerrazzanoHelidonWorkload API
definition and description is available at [VerrazzanoHelidonWorkload]({{< relref "/docs/reference/vao-oam-v1alpha1#oam.verrazzano.io/v1alpha1.VerrazzanoHelidonWorkload" >}}).

## Verrazzano Helidon application development

With Verrazzano, you manage the life cycle of applications using Component and ApplicationConfiguration resources. A Verrazzano
application can contain any number of VerrazzanoHelidonWorkload components, where each workload is a standalone
containerized Helidon application, independent of any other in the application.

In the following example, everything under the `spec:` section is the custom resource YAML file for the containerized Helidon application,
as defined by the VerrazzanoHelidonWorkload custom resource. Including this Component reference in your ApplicationConfiguration
will result in a new containerized Helidon application being provisioned.
{{< clipboard >}}

```yaml
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: hello-helidon-component
  namespace: hello-helidon
spec:
  workload:
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: VerrazzanoHelidonWorkload
    metadata:
      name: hello-helidon-workload
      labels:
        app: hello-helidon
    spec:
      deploymentTemplate:
        metadata:
          name: hello-helidon-deployment
        podSpec:
          containers:
            - name: hello-helidon-container
              ...
              ...
```

{{< /clipboard >}}

The [Steps to Deploy using OAM]({{< relref "/docs/applications/oam/deploy-app.md" >}}) provides end-to-end instructions for
developing and deploying the Verrazzano Helidon application.

For more Verrazzano Helidon application examples, see [Examples]({{< relref "/docs/examples/_index.md" >}}).

### Customizing Helidon Workload service

By default, deploying a Helidon Workload will create a service to access the Helidon pod. That service
can be customized by added a `serviceTemplate` to the `VerrazzanoHelidonWorkload` spec. This supports customizing the
service `metadata` and `serviceSpec` sections to do things, like add labels and annotations, customize the service ports,
modify the pod selector, and such. It is not necessary to provide complete `metadata` and `serviceSpec` sections. Just add the fields you
would like to customize and Verrazzano will create the rest of the fields, based the information
provided in the `deploymentTemplate`. When customizing service ports, refer to [Protocol Selection](https://istio.io/latest/docs/ops/configuration/traffic-management/protocol-selection)
in the Istio documentation.

{{< clipboard >}}
```yaml
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: hello-helidon-component
  namespace: hello-helidon
spec:
  workload:
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: VerrazzanoHelidonWorkload
    metadata:
      name: hello-helidon-workload
      labels:
        app: hello-helidon
    spec:
      deploymentTemplate:
        metadata:
          name: hello-helidon-deployment
        podSpec:
          containers:
            - name: hello-helidon-container
              ...
              ...
      serviceTemplate:
        metadata:
          name: hello-helidon-service
        serviceSpec:
          ports:
            - name: http-hello-helidon
              ...
              ...
```

{{< /clipboard >}}


### Provisioning

When you apply the previous Component YAML file, Kubernetes will create a `component.oam.verrazzano.io` resource, but
the containerized Helidon application will not be created until you create the ApplicationConfiguration resource,
which references the VerrazzanoHelidonWorkload component. When the application is created, Verrazzano creates a
Deployment and Service resource for each containerized Helidon application.

Typically, you would modify the Deployment and Service resource to make changes or to do lifecycle operations,
like scale in and scale out.  However, in the Verrazzano environment, the containerized Helidon application resource is owned
by the `verrazzano-application-operator` and will be reconciled to match the component workload resource. Therefore,
you need to manage the application configuration by modifying the VerrazzanoHelidonWorkload or ApplicationConfiguration resource,
either by `kubectl edit` or applying a new YAML file. Verrazzano will notice the Component resource change and will update
the Deployment and Service resource as needed.

You can add a new VerrazzanoHelidonWorkload to a running application, or remove an existing workload, by modifying
the ApplicationConfiguration resource and adding or removing the VerrazzanoHelidonWorkload component.

### Scaling

The recommended way to scale containerized Helidon application replicas is to specify a [ManualScalerTrait](https://github.com/oam-dev/spec/blob/v0.2.1/core/traits/manual_scaler_trait.md)
with the VerrazzanoHelidonWorkload in the ApplicationConfiguration. The following example
configuration shows the `replicaCount` field that specifies the number of replicas for the application.
{{< clipboard >}}

```yaml
...
    spec:
      components:
      - componentName: hello-helidon-component
        traits:
        - trait:                      
            apiVersion: core.oam.dev/v1alpha2
            kind: ManualScalerTrait
            spec:
              replicaCount: 2
...
```

{{< /clipboard >}}

Verrazzano will modify the Deployment resource `replicas` field and the containerized Helidon application replicas will
be scaled accordingly.

{{< alert title="NOTE" color="primary" >}}
Make sure the `replicas` defined on the VerrazzanoHelidonWorkload component and that the `replicaCount` defined on the ManualScalerTrait
for that component match, or else the DeploymentController in Kubernetes and OAM runtime in `verrazzano-application-operator`
will compete to create a different number of Pods for same containerized Helidon application. To avoid confusion,
we recommend that you specify `replicaCount` defined on the ManualScalerTrait and leave `replicas` undefined on VerrazzanoHelidonWorkload (as it is optional).
{{< /alert >}}

### Logging

When a containerized Helidon application is provisioned on Verrazzano, Verrazzano will configure the default logging
and send logs to OpenSearch. You can view the logs using the OpenSearch Dashboards.

The logs are placed in a per-namespace OpenSearch data stream named `verrazzano-application-<namespace>`,
for example: `verrazzano-application-hello-helidon`.  All logs from containerized Helidon application pods in the same namespace will
go into the same data stream, even for different applications.  This is standard behavior and there is no way to disable or change it.

### Metrics

Verrazzano uses Prometheus to scrape metrics from containerized Helidon application pods. Like logging, metrics scraping is also
enabled during provisioning. You can view metrics using the Grafana console.

Using the [MetricsTrait]({{< relref "/docs/reference/vao-oam-v1alpha1#oam.verrazzano.io/v1alpha1.MetricsTrait" >}}) custom resource, you can customize configuration
information needed to enable metrics for an application component.

### Ingress

Using the [IngressTrait]({{< relref "/docs/reference/vao-oam-v1alpha1#oam.verrazzano.io/v1alpha1.IngressTrait" >}}) custom resource, you can configure traffic
routing to a containerized Helidon application for an application component.

## Troubleshooting
Whenever you have a problem with your Verrazzano Helidon application, there are some basic techniques you
can use to troubleshoot. [Troubleshooting]({{< relref "/docs/troubleshooting/_index.md" >}}) shows you some simple
things to try, as well as how to solve common problems you may encounter.
