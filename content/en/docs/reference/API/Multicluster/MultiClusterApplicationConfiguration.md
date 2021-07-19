---
title: MultiClusterApplicationConfiguration Custom Resource Definition
linkTitle: MultiClusterApplicationConfiguration CRD
weight: 2
draft: false
---
The MultiClusterApplicationConfiguration custom resource is used to distribute `core.oam.dev/v1alpha2/ApplicationConfiguration` resources in a multicluster environment. Here is a sample MultiClusterApplicationConfiguration that specifies an ApplicationConfiguration resource to create on the cluster named `managed1`.  To deploy an example application that demonstrates a MultiClusterApplicationConfiguration, see [Multicluster Hello World Helidon]({{< relref "/docs/samples/multicluster/hello-helidon/" >}}).

```
apiVersion: clusters.verrazzano.io/v1alpha1
kind: MultiClusterApplicationConfiguration
metadata:
  name: hello-helidon-appconf
  namespace: hello-helidon
spec:
  template:
    metadata:
      annotations:
        version: v1.0.0
        description: "Hello Helidon application"
    spec:
      components:
        - componentName: hello-helidon-component
          traits:
            - trait:
                apiVersion: oam.verrazzano.io/v1alpha1
                kind: MetricsTrait
                spec:
                  scraper: verrazzano-system/vmi-system-prometheus-0
            - trait:
                apiVersion: oam.verrazzano.io/v1alpha1
                kind: IngressTrait
                metadata:
                  name: hello-helidon-ingress
                spec:
                  rules:
                    - paths:
                        - path: "/greet"
                          pathType: Prefix
  placement:
    clusters:
      - name: managed1
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

#### ApplicationConfigurationTemplate
ApplicationConfigurationTemplate has the metadata and spec of the `core.oam.dev/v1alpha2/ApplicationConfiguration` resource.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `spec` | ApplicationConfigurationSpec | An instance of the `struct` ApplicationConfigurationSpec defined in [core_types.go](https://github.com/crossplane/oam-kubernetes-runtime/blob/master/apis/core/v1alpha2/core_types.go). | No |
