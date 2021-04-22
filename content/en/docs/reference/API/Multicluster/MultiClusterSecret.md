---
title: MultiClusterSecret Custom Resource Definition
linkTitle: MultiClusterSecret Custom Resource Definition
weight: 2
draft: false
---
The MultiClusterSecret custom resource is used to distribute Kubernetes secret resources in a multicluster environment.  Here is a sample MultiClusterSecret that specifies a Kubernetes secret to create on the cluster named `managed1`.

```
apiVersion: clusters.verrazzano.io/v1alpha1
kind: MultiClusterSecret
metadata:
  name: mymcsecret
  namespace: multiclustertest
spec:
  template:
    data:
      username: dmVycmF6emFubw==
      password: dmVycmF6emFubw==
  spec:
  placement:
    clusters:
      - name: managed1
```

#### MultiClusterSecret
A MultiClusterSecret is an envelope to create Kubernetes `Secret` resources on the clusters specified in the `placement` section.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `clusters.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | `MultiClusterSecret` |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  Yes |
| `spec` |  [MultiClusterSecretSpec](#multiclustersecretspec) | The desired state of a Kubernetes secret. |  Yes |
| `status` | [MultiClusterResourceStatus](../MultiClusterResourceStatus.md) | The runtime status of a multicluster resource. | No |

#### MultiClusterSecretSpec
MultiClusterSecretSpec specifies the desired state of a Kubernetes secret.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `template` | [SecretTemplate](#secrettemplate) | The embedded Kubernetes secret. | Yes |
| `placement` | [Placement](#placement) | Clusters in which the secret is to be placed. | Yes |

#### SecretTemplate
SecretTemplate has the metadata and spec of the Kubernetes secret.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `data` | map[string][]byte | Corresponds to the `data` field of the struct `Secret` defined in [types.go](https://github.com/kubernetes/api/blob/master/core/v1/types.go). | No |
| `stringData` | map[string]string | Corresponds to the `stringData` field of the struct `Secret`  defined in [types.go](https://github.com/kubernetes/api/blob/master/core/v1/types.go). | No |
| `type` | string | Corresponds to the `type` field of the struct `Secret` defined in [types.go](https://github.com/kubernetes/api/blob/master/core/v1/types.go). | No |

#### Placement
Placement contains the name of each cluster where this resource will be located.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `clusters` | [Cluster](#cluster) array | An array of cluster locations. | Yes |

#### Cluster
Cluster contains the name of a single cluster.

Field | Type | Description | Required
| --- | --- | --- | --- |
| `cluster` | string | The name of a cluster. | Yes |