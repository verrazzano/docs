---
title: VerrazzanoProject Custom Resource Definition
linkTitle: VerrazzanoProject Custom Resource Definition
weight: 2
draft: false
---
The VerrazzanoProject custom resource is used to create the application namespaces and their associated security settings on one or more clusters.  The namespaces are always created on the admin cluster.  Here is a sample VerrazzanoProject that specifies a namespace to create on the cluster named `managed1`.

```
apiVersion: clusters.verrazzano.io/v1alpha1
kind: VerrazzanoProject
metadata:
  name: hello-helidon
  namespace: verrazzano-mc
spec:
  template:
    namespaces:
      - metadata:
          name: hello-helidon
  placement:
    clusters:
      - name: managed1
```

#### VerrazzanoProject

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `clusters.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | `VerrazzanoProject` |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  Yes |
| `spec` |  [VerrazzanoProjectSpec](#verrazzanoprojectspec) | The project specification. |  Yes |
| `status` | [MultiClusterResourceStatus](../multiclusterresourcestatus) | The runtime status of a multicluster resource. | No |

#### VerrazzanoProjectSpec
VerrazzanoProjectSpec specifies the namespaces to create and which clusters to create them on.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `template` | [ProjectTemplate](#projecttemplate) | The project template. | Yes |
| `placement` | [Placement](../placement) | Clusters on which the namespaces are to be created. | Yes |

#### ProjectTemplate
ProjectTemplate contains the list of namespaces to create and the optional security configuration for each namespace.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `namespaces` | [NamespaceTemplate](#namespacetemplate) array | The list of application namespaces to create for this project. | Yes |
| `security` | [SecuritySpec](#securityspec) | The project security configuration. | No |

#### NamespaceTemplate
NamespaceTemplate contains the metadata and spec of a Kubernetes namespace.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  Yes |
| `spec` | NamespaceSpec | An instance of the struct `NamespaceSpec` defined in [types.go](https://github.com/kubernetes/api/blob/master/core/v1/types.go). | No |

#### SecuritySpec
SecuritySpec defines the security configuration for a project.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `projectAdminSubjects` | Subject | The subject to bind to the `verrazzano-project-admin` role. Encoded as an instance of the struct `Subject` defined in [types.go](https://github.com/kubernetes/api/blob/master/rbac/v1/types.go). | No |
| `projectMonitorSubjects` | Subject | The subject to bind to the `verrazzano-project-monitoring` role. Encoded as an instance of the struct `Subject` defined in [types.go](https://github.com/kubernetes/api/blob/master/rbac/v1/types.go). | No |

