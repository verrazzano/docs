---
title: Verrazzano Workloads
weight: 2
draft: false
---

#### VerrazzanoCoherenceWorkload

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `oam.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | VerrazzanoCoherenceWorkload |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `spec` |  [VerrazzanoCoherenceWorkloadSpec](#verrazzanocoherenceworkloadspec) | The desired state of a Verrazzano Coherence workload. |  Yes |


#### VerrazzanoCoherenceWorkloadSpec
VerrazzanoCoherenceWorkloadSpec specifies the desired state of a Verrazzano Coherence workload.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `template` |  [RawExtension](https://pkg.go.dev/k8s.io/apimachinery/pkg/runtime#RawExtension) | The metadata and spec for the underlying [Coherence](https://oracle.github.io/coherence-operator/docs/3.1.3/#/about/04_coherence_spec) resource. |  Yes |


#### VerrazzanoHelidonWorkload

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `oam.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | VerrazzanoHelidonWorkload |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `spec` |  [VerrazzanoHelidonWorkloadSpec](#verrazzanohelidonworkloadspec) | The desired state of a Verrazzano Helidon workload. |  Yes |


#### VerrazzanoHelidonWorkloadSpec
VerrazzanoHelidonWorkloadSpec specifies the desired state of a Verrazzano Helidon workload.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `deploymentTemplate` |  [DeploymentTemplate](#deploymenttemplate) | The embedded deployment. |  Yes |


#### DeploymentTemplate
DeploymentTemplate specifies the metadata and pod spec of the underlying deployment.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `strategy` | [DeploymentStrategy](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#deploymentstrategy-v1-apps) | The replacement strategy of the underlying deployment. | No |
| `podSpec` | [PodSpec](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#podspec-v1-core) | The pod spec of the underlying deployment. | Yes |


#### VerrazzanoWebLogicWorkload

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `oam.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | VerrazzanoWebLogicWorkload |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `spec` |  [VerrazzanoWebLogicWorkloadSpec](#verrazzanoweblogicworkloadspec) | The desired state of a Verrazzano WebLogic workload. |  Yes |

#### VerrazzanoWebLogicWorkloadSpec
VerrazzanoWebLogicWorkloadSpec specifies the desired state of a Verrazzano WebLogic workload.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `template` |  [RawExtension](https://pkg.go.dev/k8s.io/apimachinery/pkg/runtime#RawExtension) | The metadata and spec for the underlying WebLogic [Domain](https://github.com/oracle/weblogic-kubernetes-operator/blob/main/documentation/domains/Domain.md) resource. |  Yes |
