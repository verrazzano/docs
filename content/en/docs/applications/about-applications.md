---
title: "About Applications in Verrazzano"
description: ""
weight: 1
draft: false
---

Verrazzano uses the [Open Application Model](https://oam.dev/) (OAM) specification to provide a layered approach to describing and deploying applications.
OAM is a specification developed within the [Cloud Native Computing Foundation](https://www.cncf.io/) (CNCF).
Verrazzano is compliant with the [OAM specification version 0.2.1](https://github.com/oam-dev/spec/tree/v0.2.1).

An ApplicationConfiguration is a composition of Components.
Components encapsulate application implementation details.
Application deployers apply Traits and Scopes to customize the Components for the environment.

The OAM specification supports extensibility.
The behavior of the platform can be extended by adding OAM compliant definitions and controllers.
Specifically, new workload, Trait, and Scope definitions can be added.
These definitions can be referenced by Components and application configurations and are processed by custom controllers.

![](/docs/applications/oam-arch.svg)

## Application configurations
An ApplicationConfiguration is a collection of references to Components.
A set of Traits and Scopes can be applied to each Component reference.
The platform uses these Components, Traits, and Scopes to generate the final application
resources during deployment.

The following sample shows the high level structure of an ApplicationConfiguration.
{{< clipboard >}}

```yaml
apiVersion: core.oam.dev/v1alpha2
kind: ApplicationConfiguration
...
spec:
  components:
    - componentName: example-component-1
      traits:
        ...
      scopes:
        ...
    - componentName: example-component-2
        ...
```

{{< /clipboard >}}

### Components
A Component wraps the content of a workload.
The platform extracts the workload during deployment and creates new resources that result from the application of Traits and Scopes.
Verrazzano and the OAM specification provide several workloads, for example VerrazzanoHelidonWorkload and ContainerizedWorkload.
The workloads also can be any Kubernetes resource.
For some Kubernetes resources, the `oam-kubernetes-runtime` operator may need to be granted additional permission.

A Component can also be parameterized; this allows the workload content to be customized when referenced within an ApplicationConfiguration.
See the [OAM specification](https://github.com/oam-dev/spec/blob/v0.2.1/4.component.md#spec) for details.

The following sample shows the high level structure of a Component.
{{< clipboard >}}

```yaml
apiVersion: core.oam.dev/v1alpha2
kind: Component
...
spec:
  workload:
    ...
  parameters:
    ...
```
{{< /clipboard >}}

For information about Traits, see [Verrazzano Application Traits]({{< relref "/docs/applications/oam/traits/_index.md" >}}).
<br>
For information about Workloads, see [Verrazzano Application Workloads]({{< relref "/docs/applications/oam/workloads/_index.md" >}}).

## Deployment
An application deployment occurs in Verrazzano through a number of Kubernetes controllers, reading and writing various resources.
Each controller processes application resources, and generates or updates other related resources.
Different types of controllers process different levels of application resources.

The ApplicationConfiguration controller processes ApplicationConfiguration and Component resources.
This controller extracts and stores a workload for each Component referenced within ApplicationConfiguration resources.
Verrazzano implements the ApplicationConfiguration controller within the `oam-kubernetes-runtime` operator.
Similarly, the ApplicationConfiguration controller extracts and stores Trait resources associated with Component resources in the ApplicationConfiguration.

The workload controllers process workload resources created by the ApplicationConfiguration controller, for example ContainerizedWorkload or VerrazzanoWebLogicWorkload.
This controller processes these workload resources and generates more specific runtime resources.
For example, the ContainerizedWorkload controller processes a ContainerizedWorkload resource and generates a Deployment resource.
The VerrazzanoWebLogicWorkload controller processes a VerrazzanoWebLogicWorkload resource and generates a Domain resource.
These controllers may take into account Traits and Scopes that are applied to the workload's Component references within the ApplicationConfiguration.
Verrazzano implements these workload controllers in two operators.
Verrazzano specific workloads, for example VerrazzanoHelidonWorkload, are processed by a controller within the `verrazzano-application-operator`.
Workloads defined by OAM, for example ContainerizedWorkload, are processed by a controller with the `oam-kubernetes-runtime` operator.

The Trait controllers process Trait resources created by the ApplicationConfiguration controller, for example MetricsTrait.
The ApplicationConfiguration controller records the Component to which it was applied within each extracted Trait.
The Trait controllers process extracted Trait resources, and generate or update other related resources.
For example, the IngressTrait controller within the `verrazzano-application-operator` processes IngressTrait resources and generates related Gateway and VirtualService resources.
The same operator contains a MetricsTrait controller which processes MetricsTrait resources and adds annotations to related resources such as Deployments.

Scope controllers read Scope resources updated by the ApplicationConfiguration controller during deployment.
The ApplicationConfiguration controller updates the Scope resources with references to each Component to which the Scope is applied.

The following diagram shows the relationships between the resources and controllers described previously.
![](/docs/applications/oam-flow.svg)

The following diagram, based on the `hello-helidon` example, shows the processing of resources from a Kubernetes operator perspective.
Controllers within the `oam-kubernetes-runtime` process the ApplicationConfiguration and Component resources and generate VerrazzanoHelidonWorkload and IngressTrait.
Then controllers within the `verrazzano-application-operator` process the VerrazzanoHelidonWorkload and IngressTrait resources to generate Deployment, VirtualService, and other resources.

![](/docs/applications/hello-helidon.svg)
