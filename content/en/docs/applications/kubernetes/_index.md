---
title: "Deploy Applications Using Kubernetes Objects"
weight: 3
draft: false
---

Verrazzano and OAM provide workloads and Traits to define and customize applications.
However, some situations may require resources beyond those provided.
In those cases, you can use other existing Kubernetes resources.
The `todo-list` example takes advantage of this capability in several Components to support unique Service and ConfigMap requirements.

Most Kubernetes resources can be embedded as a workload within a Component.
The following sample shows how a Deployment can be embedded as a workload within a Component.
The `oam-kubernetes-runtime` operator will process the Component and extract the Deployment to a separate resource during deployment.
{{< clipboard >}}

```yaml
apiVersion: core.oam.dev/v1alpha2
kind: Component
...
spec:
  workload:
    kind: Deployment
    apiVersion: apps/v1
    name: ...
    spec:
      selector:
        ...
      template:
        ...
```
{{< /clipboard >}}

Most Kubernetes resources can also be embedded as a Trait within an ApplicationConfiguration.
The following sample shows how an Ingress can be embedded as a trait within an ApplicationConfiguration.
The `oam-kubernetes-runtime` operator will process the ApplicationConfiguration and extract the Ingress to a separate resource during deployment.
In the following sample, note that the Ingress is the Kubernetes Ingress, not the IngressTrait provided by Verrazzano.
{{< clipboard >}}

```yaml
apiVersion: core.oam.dev/v1alpha2
kind: ApplicationConfiguration
...
spec:
  components:
    - componentName: ...
      traits:
        - trait:
            apiVersion: networking.k8s.io/v1beta1
            kind: Ingress
            ...
            spec:
              rules:
                ...
```
{{< /clipboard >}}
The `oam-kubernetes-runtime` operator has the following limited set of cluster role privileges, by default.

| API Groups | Resources | Verbs |
| --- | --- | --- |
| | `configmaps`, `events`, `services` | `create`, `delete`, `deletecollection`, `get`, `list`, `patch`, `update`, `watch` |
| | `persistentvolumeclaims` |  `create`, `delete`, `deletecollection`, `get`, `list`, `patch`, `update` |
| `apps` | `deployments`, `controllerrevisions` |  `create`, `delete`, `deletecollection`, `get`, `list`, `patch`, `update`, `watch` |
| `core.oam.dev` | `*` |  `create`, `delete`, `deletecollection`, `get`, `list`, `patch`, `update`, `watch` |
| `oam.verrazzano.io` | `*` |  `create`, `delete`, `deletecollection`, `get`, `list`, `patch`, `update`, `watch` |

Your cluster administrator may need to grant the `oam-kubernetes-runtime` operator additional privileges to enable the use of some Kubernetes resources as workloads or traits.
Create additional roles and role bindings for the specific resources to be embedded as workloads or traits.
The following examples of ClusterRole and ClusterRoleBinding show how `oam-kubernetes-runtime` can be granted privileges to manage Ingress resources.
{{< clipboard >}}

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: oam-kubernetes-runtime-ingresses
rules:
  - apiGroups:
    - networking.k8s.io
    - extensions
    resources:
    - ingresses
    verbs:
    - create
    - delete
    - get
    - list
    - patch
    - update
```

{{< /clipboard >}}

{{< clipboard >}}

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: oam-kubernetes-runtime-ingresses
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: oam-kubernetes-runtime-ingresses
subjects:
  - kind: ServiceAccount
    name: oam-kubernetes-runtime
    namespace: verrazzano-system
```
{{< /clipboard >}}
