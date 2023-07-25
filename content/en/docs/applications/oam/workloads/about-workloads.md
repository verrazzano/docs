---
title: "About Verrazzano Workloads"
weight: 2
draft: false
---

Components contain an embedded workload.
Verrazzano and the OAM specification provide several workloads, for example VerrazzanoWebLogicWorkload and ContainerizedWorkload.
Workloads can also be any Kubernetes resource.

The following sample shows a VerrazzanoHelidonWorkload workload embedded within a Component.
{{< clipboard >}}

```yaml
apiVersion: core.oam.dev/v1alpha2
kind: Component
...
spec:
  workload:
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: VerrazzanoHelidonWorkload
    spec:
      deploymentTemplate:
        podSpec:
          containers:
            - name: example-container
              image: ...
              ...
```
{{< /clipboard >}}

A workload can optionally have an associated WorkloadDefinition.
This provides the platform with information about the schema of the workload.
A WorkloadDefintion is typically provided by the platform, not an end user.


### Scopes
Scopes customize Component workloads and generate related resources during deployment.
An ApplicationConfiguration contains Scope references instead of the Scope's content being embedded.
The platform will update the Scopes with a reference to each applied Component.
This update triggers the related operator to process the Scope.

The following sample shows a reference to a HealthScope named `example-health-scope`.
{{< clipboard >}}
```yaml
apiVersion: core.oam.dev/v1alpha2
kind: ApplicationConfiguration
...
spec:
  components:
    - componentName: example-component
      scopes:
        - scopeRef:
            apiVersion: core.oam.dev/v1alpha2
            kind: HealthScope
            name: example-health-scope
        ...
```
{{< /clipboard >}}

The following sample shows the configuration details of the referenced HealthScope.
{{< clipboard >}}

```yaml
apiVersion: core.oam.dev/v1alpha2
kind: HealthScope
metadata:
  name: example-health-scope
spec:
  probe-method: GET
  probe-endpoint: /health
```
{{< /clipboard >}}

Each Scope type can optionally have an associated ScopeDefinition.
This provides the platform with additional information about processing the Scope:
- The Scope's schema
- The workload types to which the Scope can be applied
- The field within the Scope used to record related Component references

A ScopeDefintion is typically provided by the platform, not an end user.

The Verrazzano platform provides several workload definitions and implementations:

- The VerrazzanoWebLogicWorkload is used for WebLogic workloads. See [WebLogic Workload]({{< relref "/docs/applications/oam/workloads/weblogic/_index.md" >}}).
- The VerrazzanoCoherenceWorkload is used for Coherence workloads. See [Coherence Workload]({{< relref "/docs/applications/oam/workloads/coherence/coherence.md" >}}).
- The VerrazzanoHelidonWorkload is used for Helidon workloads. See [Helidon Workload]({{< relref "/docs/applications/oam/workloads/helidon/helidon.md" >}}).


### OAM ContainerizedWorkload
The ContainerizedWorkload should be used for long-running container workloads which are not covered by the workload types described previously.
This workload type is similar to the Deployment workload.
It is provided to ensure that OAM can be used for non-Kubernetes deployment environments.
See the [OAM specification](https://github.com/oam-dev/spec/blob/v0.2.1/core/workloads/containerized_workload/containerized_workload.md).
