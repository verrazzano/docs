---
title: MultiClusterLoggingScope Custom Resource Definition
linkTitle: MultiClusterLoggingScope Custom Resource Definition
weight: 2
draft: false
---
The MultiClusterLoggingScope custom resource is used to distribute `core.oam.dev/v1alpha2/LoggingScope` resources in a multicluster environment. Here is a sample MultiClusterLoggingScope that specifies a LoggingScope resource to create on the cluster named `managed1`.

```
apiVersion: clusters.verrazzano.io/v1alpha1
kind: MultiClusterLoggingScope
metadata:
  name: unit-mclogscope
  namespace: unit-mclogscope-namespace
  labels:
    label1: test1
spec:
  template:
    spec:
      fluentdImage: myFluentdImage:v123
      elasticSearchURL: http://myLocalEsHost:9200
      secretName: logScopeSecret
      workloadRefs: []
  placement:
    clusters:
      - name: managed1
```

#### MultiClusterLoggingScope
A MultiClusterLoggingScope is an envelope to create `core.oam.dev/v1alpha2/LoggingScope` resources on the clusters specified in the `placement` section.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `clusters.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | `MultiClusterLoggingScope` |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  Yes |
| `spec` |  [MultiClusterLoggingScopeSpec](#multiclusterloggingscopespec) | The desired state of a `core.oam.dev/v1alpha2/LoggingScope` resource. |  Yes |
| `status` | [MultiClusterResourceStatus](../multiclusterresourcestatus) | The runtime status of a multicluster resource. | No |

#### MultiClusterLoggingScopeSpec
MultiClusterLoggingScopeSpec specifies the desired state of a `core.oam.dev/v1alpha2/LoggingScope` resource.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `template` | [LoggingScopeTemplate](#loggingscopetemplate) | The embedded `core.oam.dev/v1alpha2/LoggingScope` resource. | Yes |
| `placement` | [Placement](#placement) | Clusters in which the resource is to be placed. | Yes |

#### LoggingScopeTemplate
LoggingScopeTemplate has the metadata and spec of the `core.oam.dev/v1alpha2/LoggingScope` resource.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `spec` | ComponentSpec | An instance of the struct `LoggingScopeSpec` defined in [core_types.go](https://github.com/crossplane/oam-kubernetes-runtime/blob/master/apis/core/v1alpha2/core_types.go). | No |

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


