---
title: MultiClusterResourceStatus Subresource
weight: 2
draft: false
---
The MultiClusterResourceStatus subresource is shared by multicluster custom resources.

#### MultiClusterResourceStatus
MultiClusterResourceStatus specifies the status portion of a multicluster resource.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `conditions` | [Condition](#condition) array | The current state of a multicluster resource. | No |
| `state` | string | The state of the multicluster resource.  State values are case-sensitive and formatted as follows: <ul><li>`Pending`: deployment to cluster is in progress</li><li>`Succeeded`: deployment to cluster successfully completed</li><li>`Failed`: deployment to cluster failed</li></ul> | No |
| `clusters` | [ClusterLevelStatus](#clusterlevelstatus) array | Array of status information for each cluster. | No |

#### Condition
Condition describes current state of a multicluster resource across all clusters.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `type` | string | The condition of the multicluster resource which can be checked with a `kubectl wait` command. Condition values are case-sensitive and formatted as follows: <ul><li>`DeployComplete`: deployment to all clusters completed successfully</li><li>`DeployFailed`: deployment to all clusters failed</li></ul> | Yes |
| `status` | ConditionStatus | An instance of the type ConditionStatus that is defined in [types.go](https://github.com/kubernetes/api/blob/master/core/v1/types.go). | Yes |
| `lastTransitionTime` | string | The last time the condition transitioned from one status to another. | No |
| `message` | string | A message with details about the last transition. | No |


#### ClusterLevelStatus
ClusterLevelStatus describes the status of the multicluster resource on an individual cluster.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `name` | string | Name of the cluster. | Yes |
| `state` | string | The state of the multicluster resource.  State values are case-sensitive and formatted as follows: <ul><li>`Pending`: deployment is in progress</li><li>`Succeeded`: deployment successfully completed</li><li>`Failed`: deployment failed</li></ul> | No |
| `message` | string | Message with details about the status in this cluster. | No |
| `lastUpdateTime` | string | The last time the resource state was updated. | Yes |
