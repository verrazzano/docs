---
title: MultiClusterApplicationConfiguration
weight: 2
draft: false
---

#### MultiClusterApplicationConfiguration
A MultiClusterApplicationConfiguration is an envelope to create `core.oam.dev/v1alpha2/ApplicationConfiguration` resources on the clusters specified in the `placement` section.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `clusters.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | MultiClusterApplicationConfiguration |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  Yes |
| `spec` |  [MultiClusterApplicationConfigurationSpec](#multiclusterapplicationconfigurationspec) | The desired state of a `core.oam.dev/v1alpha2/ApplicationConfiguration` resource. |  Yes |
| `status` | [MultiClusterResourceStatus](../multiclusterresourcestatus) | The runtime status of a multicluster resource. | No |

#### MultiClusterApplicationConfigurationSpec
MultiClusterApplicationConfigurationSpec specifies the desired state of a `core.oam.dev/v1alpha2/ApplicationConfiguration` resource.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `template` | [ApplicationConfigurationTemplate](#applicationconfigurationtemplate) | The embedded `core.oam.dev/v1alpha2/ApplicationConfiguration` resource. | Yes |
| `placement` | [Placement](../placement) | Clusters in which the resource is to be placed. | Yes |
| `secrets` | string array | List of secrets used by the application.  These secrets must be created in the application's namespace before deploying a MultiClusterApplicationConfiguration resource. | No |

#### ApplicationConfigurationTemplate
ApplicationConfigurationTemplate has the metadata and spec of the `core.oam.dev/v1alpha2/ApplicationConfiguration` resource.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `spec` | ApplicationConfigurationSpec | An instance of the `struct` ApplicationConfigurationSpec defined in [core_types.go](https://github.com/crossplane/oam-kubernetes-runtime/blob/master/apis/core/v1alpha2/core_types.go). | No |
