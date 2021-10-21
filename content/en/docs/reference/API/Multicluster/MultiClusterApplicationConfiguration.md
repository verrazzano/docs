---
title: MultiClusterApplicationConfiguration Custom Resource Definition
linkTitle: MultiClusterApplicationConfiguration CRD
weight: 2
draft: false
---
The MultiClusterApplicationConfiguration custom resource is an envelope used to distribute `core.oam.dev/v1alpha2/ApplicationConfiguration` resources in a multicluster environment.

Here is a sample MultiClusterApplicationConfiguration that specifies an ApplicationConfiguration resource to create on the cluster named `managed1`.  To deploy an example application that demonstrates a MultiClusterApplicationConfiguration, see [Multicluster ToDo List]({{< relref "/docs/samples/multicluster/todo-list/" >}}).

```
apiVersion: clusters.verrazzano.io/v1alpha1
kind: MultiClusterApplicationConfiguration
metadata:
  name: todo-appconf
  namespace: mc-todo-list
spec:
  template:
    metadata:
      annotations:
        version: v1.0.0
        description: "ToDo List example application"
    spec:
      components:
        - componentName: todo-domain
          traits:
            - trait:
                apiVersion: oam.verrazzano.io/v1alpha1
                kind: MetricsTrait
                spec:
                  scraper: verrazzano-system/vmi-system-prometheus-0
            - trait:
                apiVersion: oam.verrazzano.io/v1alpha1
                kind: IngressTrait
                spec:
                  rules:
                    - paths:
                        - path: "/todo"
                          pathType: Prefix
        - componentName: todo-jdbc-config
        - componentName: mysql-initdb-config
        - componentName: todo-mysql-service
        - componentName: todo-mysql-deployment
  placement:
    clusters:
      - name: managed1
  secrets:
    - tododomain-repo-credentials
    - tododomain-jdbc-tododb
    - tododomain-weblogic-credentials
```

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
