---
title: Configure Verrazzano on Managed Clusters
linkTitle: Configure Verrazzano on Managed Clusters
weight: 9
draft: false
---

When you provision new clusters using the cluster API component, you can choose to also install Verrazzano on them. You can then use VerrazzanoFleet, a cluster API add-on, to perform lifecycle management operations on Verrazzano installations on your managed clusters.

## Configure VerrazzanoFleet

Before you can manage Verrazzano on your managed clusters, you need to configure the VerrazzanoFleet resource.

1. Provision OCNE or OKE clusters. For instructions, see:
    * [Create OCNE Clusters Running on OCI]({{< relref "/docs/setup/provision-cluster/ocne-oci" >}})
    * [Create OKE Clusters Running on OCI]({{< relref "/docs/setup/provision-cluster/oke-oci" >}})
2. Identify the namespace where the new cluster resides:

{{< clipboard >}}
<div class="highlight">

```
$ kubectl get clusters.cluster.x-k8s.io -A
```
{{< /clipboard >}}
</div>

3. Create a VerrazzanoFleet resource. The following example creates a typical `VerrazzanoFleet` resource.

{{< clipboard >}}
<div class="highlight">

```
$   kubectl apply -f - <<EOF
    apiVersion: addons.cluster.x-k8s.io/v1alpha1
    kind: VerrazzanoFleet
    metadata:
      name: example-fleet-1
      namespace: default
    spec:
      clusterSelector:
        name: cluster1
      verrazzano:
        spec:
          profile: managed-cluster
EOF
```
{{< /clipboard >}}
</div>


## Customize a remote Verrazzano installation

By default, new managed clusters are provisioned with the Verrazzano `managed-cluster` profile. If you want to enable more components, disable unnecessary ones, or modify the settings of a component, then you can edit the `verrazzano.spec` object of the VerrazzanoFleet resource to suit your needs. 

Use the same process to edit the `verrazzano.spec` object as you would the Verrazzano resource. For more information, see [Modify Verrazzano Installations]({{< relref "/docs/setup/modify-installation" >}}).

Refer to [Profile Configurations]({{< relref "/docs/setup/install/perform/profiles#profile-configurations" >}}) to see which components are already enabled in a `managed-cluster` profile.

The following configuration shows you how to enable Argo CD and Velero:

{{< clipboard >}}
<div class="highlight">

```
$   kubectl apply -f - <<EOF
    apiVersion: addons.cluster.x-k8s.io/v1alpha1
    kind: VerrazzanoFleet
    metadata:
      name: example-fleet-1
      namespace: default
    spec:
      clusterSelector:
        name: cluster1
      verrazzano:
        spec:
          profile: managed-cluster
          components:
            argoCD:
              enabled: true
            velero: 
              enabled: true
            
EOF
```
{{< /clipboard >}}
</div>

## Upgrade Verrazzano on managed clusters

You can upgrade the Verrazzano installation on managed clusters.

1. Upgrade the Verrazzano installation on the admin cluster. For instructions, see [Upgrade Verrazzano]({{< relref "/docs/setup/upgrade/perform" >}}).
1. In the VerrazzanoFleet resource, use component overrides to upgrade `VerrazzanoFleet.spec.verrazzano.spec.version`. The Verrazzano version on the managed clusters must match the version of the admin cluster.

In this example, the managed clusters are upgraded to Verrazzano 1.7.0.

{{< clipboard >}}
<div class="highlight">

```
$   kubectl apply -f - <<EOF
    apiVersion: addons.cluster.x-k8s.io/v1alpha1
    kind: VerrazzanoFleet
    metadata:
      name: example-fleet-1
      namespace: default
    spec:
      clusterSelector:
        name: cluster1 
      verrazzano:
        spec:
          profile: managed-cluster
          version: 1.7.0
EOF
```
{{< /clipboard >}}
</div>


## Use a private registry

You can manage your managed clusters even when they are installed in a disconnected environment. Use component overrides to configure the VerrazzanoFleet resource to access a private registry.

To connect to a private registry, you need to configure the following component overrides: 

* `VerrazzanoFleet.spec.imagePullSecrets.name`
* `VerrazzanoFleet.spec.image.repository`
* `VerrazzanoFleet.spec.image.tag`
* `VerrazzanoFleet.spec.privateRegistry.enabled`

For example: 
{{< clipboard >}}
<div class="highlight">

```
$   kubectl apply -f - <<EOF
    apiVersion: addons.cluster.x-k8s.io/v1alpha1
    kind: VerrazzanoFleet
    metadata:
      name: example-fleet-1
      namespace: default
    spec:
      clusterSelector:
        name: cluster1
      imagePullSecrets:
      - name: verrazzano-container-registry
      image:
        repository: ${OCNE_IMAGE_REPOSITORY=ghcr.io}/${VZ_IMAGE_PATH=verrazzano}
        tag: ${VERRAZZANO_PLATFORM_OPERATOR_IMAGE_TAG}
      privateRegistry:
         enabled: true
      verrazzano:
        spec:
          profile: managed-cluster
EOF
```
{{< /clipboard >}}
</div>

## Remove Verrazzano from managed clusters

You can remove the Verrazzano installation from managed clusters.

1. On the admin cluster, run this command:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl delete vf -n <namespace> <name of verrazzanofleet>
```
{{< /clipboard >}}
</div>

When a VerrazzanoFleet object is deleted, it removes Verrazzano from the cluster which was associated to the fleet.