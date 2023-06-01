---
title: "About Verrazzano Traits"
description: "Learn about Verrazzano traits"
weight: 2
draft: false
---

Traits customize Component workloads and generate related resources during deployment.
Verrazzano provides several Traits, for example IngressTrait and MetricsTrait.
The platform extracts Traits contained within an ApplicationConfiguration during deployment.
This processing is similar to the extraction of workload content from Component resources.
Note that for some Kubernetes resources, the `oam-kubernetes-runtime` operator may need to be granted `create` permission.

A Kubernetes operator, for example `verrazzano-application-operator`, processes these extracted Traits and may create additional related resources or may alter related workloads.
Each Trait implementation will behave differently.

The following sample shows an IngressTrait applied to a referenced Component.
{{< clipboard >}}

```yaml
apiVersion: core.oam.dev/v1alpha2
kind: ApplicationConfiguration
...
spec:
  components:
    - componentName: example-component
      traits:
        - trait:
            apiVersion: oam.verrazzano.io/v1alpha1
            kind: IngressTrait
            spec:
              rules:
                - paths:
                    - path: "/greet"
```
{{< /clipboard >}}

Each Trait type optionally can have an associated TraitDefinition.
This provides the platform with additional information about the Trait's schema and workloads to which the Trait can be applied.
A TraitDefintion is typically provided by the platform, not an end user.

The Verrazzano platform provides several Trait definitions and implementations:

- [IngressTrait]({{< relref "/docs/applications/oam/traits/ingress/ingress" >}})
- [MetricsTrait]({{< relref "/docs/applications/oam/traits/metrics/metrics" >}})
- [LoggingTrait]({{< relref "/docs/applications/oam/traits/logging/logging" >}})
