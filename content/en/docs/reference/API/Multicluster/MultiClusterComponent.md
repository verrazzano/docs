---
title: MultiClusterComponent Custom Resource Definition
linkTitle: MultiClusterComponent CRD
weight: 2
draft: false
---
The MultiClusterComponent custom resource is used to distribute `core.oam.dev/v1alpha2/Component` resources in a multicluster environment. Here is a sample MultiClusterComponent that specifies a OAM component resource to create on the cluster named `managed1`.  To deploy an example application that demonstrates a MultiClusterComponent, see [Multicluster Hello World Helidon]({{< relref "/docs/samples/multicluster/hello-helidon/" >}}).

```
apiVersion: clusters.verrazzano.io/v1alpha1
kind: MultiClusterComponent
metadata:
  name: hello-helidon-component
  namespace: hello-helidon
spec:
  template:
    spec:
      workload:
        apiVersion: oam.verrazzano.io/v1alpha1
        kind: VerrazzanoHelidonWorkload
        metadata:
          name: hello-helidon-workload
          namespace: hello-helidon
          labels:
            app: hello-helidon
        spec:
          deploymentTemplate:
            metadata:
              name: hello-helidon-deployment
            podSpec:
              containers:
                - name: hello-helidon-container
                  image: "ghcr.io/verrazzano/example-helidon-greet-app-v1:0.1.12-1-20210409130027-707ecc4"
                  ports:
                    - containerPort: 8080
                      name: http
  placement:
    clusters:
      - name: managed1
```

#### MultiClusterComponent
A MultiClusterComponent is an envelope to create `core.oam.dev/v1alpha2/Component` resources on the clusters specified in the `placement` section.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `clusters.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | MultiClusterComponent |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  Yes |
| `spec` |  [MultiClusterComponentSpec](#multiclustercomponentspec) | The desired state of a `core.oam.dev/v1alpha2/Component` resource. |  Yes |
| `status` | [MultiClusterResourceStatus](../multiclusterresourcestatus) | The runtime status of a multicluster resource. | No |

#### MultiClusterComponentSpec
MultiClusterComponentSpec specifies the desired state of a `core.oam.dev/v1alpha2/Component` resource.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `template` | [ComponentTemplate](#componenttemplate) | The embedded `core.oam.dev/v1alpha2/Component` resource. | Yes |
| `placement` | [Placement](../placement) | Clusters in which the resource is to be placed. | Yes |

#### ComponentTemplate
ComponentTemplate has the metadata and spec of the `core.oam.dev/v1alpha2/Component` resource.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `spec` | ComponentSpec | An instance of the `struct` ComponentSpec defined in [core_types.go](https://github.com/crossplane/oam-kubernetes-runtime/blob/master/apis/core/v1alpha2/core_types.go). | No |
