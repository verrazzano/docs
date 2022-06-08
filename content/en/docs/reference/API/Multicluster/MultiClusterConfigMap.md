---
title: MultiClusterConfigMap Custom Resource Definition
linkTitle: MultiClusterConfigMap CRD
weight: 2
draft: false
---
The MultiClusterConfigMap custom resource is an envelope used to distribute Kubernetes ConfigMap resources in a multicluster environment.

{{< alert title="NOTE" color="warning" >}}
Starting with Verrazzano v1.1.0, it is preferred that the MultiClusterConfigMap custom resource not be used; instead
directly use `core.oam.dev/v1alpha2/Component` to define ConfigMap resources in your application.
See the example application, [Multicluster ToDo List]({{< relref "/docs/samples/multicluster/todo-list/" >}}), which uses `core.oam.dev/v1alpha2/Component` resources to define ConfigMaps.
{{< /alert >}}

Here is a sample MultiClusterConfigMap that specifies a Kubernetes ConfigMap to create on the cluster named `managed1`.

```
apiVersion: clusters.verrazzano.io/v1alpha1
kind: MultiClusterConfigMap
metadata:
  name: mymcconfigmap
  namespace: multiclustertest
spec:
  template:
    metadata:
      name: myconfigmap
      namespace: myns
    data:
      simple.key: "simplevalue"
  placement:
    clusters:
      - name: managed1
```

#### MultiClusterConfigMap
A MultiClusterConfigMap is an envelope to create Kubernetes ConfigMap resources on the clusters specified in the `placement` section.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `clusters.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | MultiClusterConfigMap |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  Yes |
| `spec` |  [MultiClusterConfigMapSpec](#multiclusterconfigmapspec) | The desired state of a Kubernetes ConfigMap. |  Yes |
| `status` | [MultiClusterResourceStatus](../multiclusterresourcestatus) | The runtime status of a multicluster resource. | No |

#### MultiClusterConfigMapSpec
MultiClusterConfigMapSpec specifies the desired state of a Kubernetes ConfigMap.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `template` | [ConfigMapTemplate](#configmaptemplate) | The embedded Kubernetes ConfigMap. | Yes |
| `placement` | [Placement](../placement) | Clusters in which the ConfigMap is to be placed. | Yes |

#### ConfigMapTemplate
ConfigMapTemplate has the metadata and spec of the Kubernetes ConfigMap.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `immutable` | *bool | Corresponds to the `immutable` field of the `struct` ConfigMap defined in [types.go](https://github.com/kubernetes/api/blob/master/core/v1/types.go). | No |
| `data` | map[string]string | Corresponds to the `data` field of the `struct` ConfigMap defined in [types.go](https://github.com/kubernetes/api/blob/master/core/v1/types.go). | No |
| `binaryData` | map[string][]byte | Corresponds to the `binaryData` field of the `struct` ConfigMap  defined in [types.go](https://github.com/kubernetes/api/blob/master/core/v1/types.go). | No |
