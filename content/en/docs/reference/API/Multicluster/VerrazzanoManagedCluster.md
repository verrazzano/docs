---
title: VerrazzanoManagedCluster Custom Resource Definition
linkTitle: VerrazzanoManagedCluster Custom Resource Definition
weight: 2
draft: false
---
The VerrazzanoManagedCluster custom resource is used to register a managed cluster with an admin cluster.  Here is a sample VerrazzanoManagedCluster that registers the cluster named `managed1`.  To deploy an example application that demonstrates a VerrazzanoManagedCluster, see [Multicluster Hello World Helidon](https://github.com/verrazzano/verrazzano/blob/master/examples/multicluster/hello-helidon/README.md).

```
apiVersion: clusters.verrazzano.io/v1alpha1
kind: VerrazzanoManagedCluster
metadata:
  name: managed1
  namespace: verrazzano-mc
spec:
  description: "Managed Cluster 1"
  prometheusSecret: prometheus-managed1
```

#### VerrazzanoManagedCluster

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `clusters.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | `VerrazzanoManagedCluster` |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  Yes |
| `spec` |  [VerrazzanoManagedClusterSpec](#verrazzanomanagedclusterspec) | The managed cluster specification. |  Yes |
| `status` | [VerrazzanoManagedClusterStatus](#verrazzanomanagedclusterstatus) | The runtime status this resource. | No |

#### VerrazzanoManagedClusterSpec
VerrazzanoManagedClusterSpec specifies a managed cluster to associate with an admin cluster.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `description` | string | The description of the managed cluster. | No |
| `prometheusSecret` | string | The name of a Secret that contains the credentials for scraping from the Prometheus endpoint on the managed cluster. See the [instructions](#instructions-to-create-prometheussecret) for how to create this Secret.| Yes |
| `serviceAccount` | string | The name of the ServiceAccount that was generated for the managed cluster. This field is managed by a Verrazzano Kubernetes operator. | No |
| `managedClusterManifestSecret` | string | The name of the Secret containing generated YAML manifest file to be applied by the user to the managed cluster. This field is managed by a Verrazzano Kubernetes operator. | No |

#### VerrazzanoManagedClusterStatus

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `conditions` | [Condition](#condition) array | The current state of this resource. | No |
| `lastAgentConnectTime` | string | The last time the agent from this managed cluster connected to the admin cluster. | No |
| `apiUrl` | string | The Verrazzano API server URL for the managed cluster. | No |

#### Condition
Condition describes current state of this resource.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `type` | string | The condition of the multicluster resource which can be checked with a `kubectl wait` command. Condition values are case-sensitive and formatted as follows: `Ready`: the VerrazzanoManagedCluster is ready to be used and all resources needed have been generated. | Yes |
| `status` | ConditionStatus | An instance of the type `ConditionStatus` that is defined in [types.go](https://github.com/kubernetes/api/blob/master/core/v1/types.go). | Yes |
| `lastTransitionTime` | string | The last time the condition transitioned from one status to another. | No |
| `message` | string | A message with details about the last transition. | No |

#### Instructions to create prometheusSecret
Instructions to create the Secret that is referenced in the field `prometheusSecret`.
```
$ CLUSTER_NAME=managed2
$ echo "prometheus:" > ${CLUSTER_NAME}.yaml
$ echo "  host: $(kubectl get ing vmi-system-prometheus -n verrazzano-system -o jsonpath='{.spec.tls[0].hosts[0]}')" >> ${CLUSTER_NAME}.yaml
$ CA_CERT=$(kubectl -n verrazzano-system get secret system-tls -o json | jq -r '.data."ca.crt"' | base64 --decode)
$ echo "  cacrt: |" >> ${CLUSTER_NAME}.yaml
$ echo -e "$CA_CERT" | sed 's/^/    /' >> ${CLUSTER_NAME}.yaml
$ kubectl create secret generic prometheus-${CLUSTER_NAME} -n verrazzano-mc --from-file=${CLUSTER_NAME}.yaml
```

