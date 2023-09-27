---
title: MultiClusterSecret
weight: 2
draft: false
---
The MultiClusterSecret custom resource is an envelope used to distribute Kubernetes Secret resources in a multicluster environment.

{{< alert title="NOTE" color="warning" >}}
Starting with Verrazzano v1.1.0, it is preferred that the MultiClusterSecret custom resource not be used; instead
specify secrets in the MultiClusterApplicationConfiguration resource.
See the example application, [Multicluster ToDo List]({{< relref "/docs/samples/multicluster/todo-list/" >}}) where secrets are specified in a MultiClusterApplicationConfiguration resource.
{{< /alert >}}

Here is a sample MultiClusterSecret that specifies a Kubernetes secret to create on the cluster named `managed1`.

```
apiVersion: clusters.verrazzano.io/v1alpha1
kind: MultiClusterSecret
metadata:
  name: mymcsecret
  namespace: multiclustertest
spec:
  template:
    data:
      username: <base64-encoded username>
      password: <base64-encoded password>
  spec:
  placement:
    clusters:
      - name: managed1
```

#### MultiClusterSecret
A MultiClusterSecret is an envelope to create Kubernetes Secret resources on the clusters specified in the `placement` section.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `clusters.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | MultiClusterSecret |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  Yes |
| `spec` |  [MultiClusterSecretSpec](#multiclustersecretspec) | The desired state of a Kubernetes Secret. |  Yes |
| `status` | [MultiClusterResourceStatus](../multiclusterresourcestatus) | The runtime status of a multicluster resource. | No |

#### MultiClusterSecretSpec
MultiClusterSecretSpec specifies the desired state of a Kubernetes Secret.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `template` | [SecretTemplate](#secrettemplate) | The embedded Kubernetes Secret. | Yes |
| `placement` | [Placement](../placement) | Clusters in which the Secret is to be placed. | Yes |

#### SecretTemplate
SecretTemplate has the metadata and spec of the Kubernetes Secret.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `data` | map[string][]byte | Corresponds to the `data` field of the `struct` Secret defined in [types.go](https://github.com/kubernetes/api/blob/master/core/v1/types.go). | No |
| `stringData` | map[string]string | Corresponds to the `stringData` field of the `struct` Secret  defined in [types.go](https://github.com/kubernetes/api/blob/master/core/v1/types.go). | No |
| `type` | string | Corresponds to the `type` field of the `struct` Secret defined in [types.go](https://github.com/kubernetes/api/blob/master/core/v1/types.go). | No |
