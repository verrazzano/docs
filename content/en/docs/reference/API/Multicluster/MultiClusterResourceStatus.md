---
title: MultiClusterResourceStatus Struct
linkTitle: MultiClusterResourceStatus Struct
weight: 2
draft: false
---
The MultiClusterResourceStatus is a struct that is shared by all multicluster custom resources.

#### MultiClusterResourceStatus
MultiClusterResourceStatus specifies the status portion of a multicluster resource.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `conditions` | [Condition](#condition) array | The current state of a multicluster resource. | No |

#### Condition
Condition describes current state of a multicluster resource.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `type` | string | The condition of the multi-cluster resource which can be checked with `kubectl wait` command. Condition values are case-sensitive and formatted as follows: <ul><li>`DeployComplete`: deployment to specified cluster completed successfully</li><li>`DeployFailed`: deployment to specified cluster failed</li></ul> | Yes |
| `status` | ConditionStatus | An instance of the type `ConditionStatus` defined in [types.go](https://github.com/kubernetes/api/blob/master/core/v1/types.go). | Yes |
| `lastTransitionTime` | string | The last time the condition transitioned from one status to another. | No |
| `message` | string | A message indicating details about the last transition. | No |


#### ConditionType


