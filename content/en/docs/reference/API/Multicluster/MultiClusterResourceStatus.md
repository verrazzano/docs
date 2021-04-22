---
title: MultiClusterResourceStatus Custom Resource Definition
linkTitle: MultiClusterResourceStatus Custom Resource Definition
weight: 2
draft: false
---
The MultiClusterResourceStatus is a struct that is shared by all multicluster custom resources.

#### MultiClusterResourceStatus
MultiClusterResourceStatus specifies the status portion of a multicluster resource.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `template` | [SecretTemplate](#secrettemplate) | The embedded Kubernetes secret. | Yes |
| `placement` | [Placement](#placement) | Clusters in which the secret is to be placed. | Yes |

