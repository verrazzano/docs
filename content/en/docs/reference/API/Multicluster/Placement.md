---
title: Placement Subresource
linkTitle: Placement Subresource
weight: 2
draft: false
---
The Placement subresource is shared by multicluster custom resources.

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


