---
title: "Install Multicluster"
description: "How to set up a multicluster Verrazzano environment"
weight: 1
draft: false
---

## Prerequisites

- Before you begin, read this document, [Verrazzano in a multicluster environment]({{< relref "/docs/concepts/VerrazzanoMultiCluster.md" >}}).
- To set up a multicluster Verrazzano environment, you will need two or more Kubernetes clusters. One of these clusters
will be *admin* cluster; the others will be *managed* clusters. For instructions on preparing Kubernetes platforms for installing Verrazzano, see [Platform Setup]({{< relref "/docs/setup/platforms/_index.md" >}}).

{{< alert title="NOTE" color="primary" >}}
If Rancher is not enabled, then refer to [Verrazzano multicluster installation without Rancher]({{< relref "docs/setup/install/mc-install/multicluster-no-rancher.md" >}})
because additional steps are required to register a managed cluster.
{{< /alert >}}

The following instructions assume an admin cluster and a single managed cluster. For each additional managed
cluster, simply repeat the managed cluster instructions.

## Install Verrazzano

To install Verrazzano on each Kubernetes cluster, complete the following steps:

1. On one cluster, install Verrazzano using the `dev` or `prod` profile; this will be the *admin* cluster.
2. On the other cluster, install Verrazzano using the `managed-cluster` profile; this will be a managed cluster. The `managed-cluster` profile contains only the components that are required for a managed cluster.
<br>**NOTE**: You also can use the `dev` or `prod` profile.

For detailed instructions on how to install and customize Verrazzano on a Kubernetes cluster using a specific profile,
see the [Installation Guide]({{< relref "/docs/setup/install/" >}}) and [Installation Profiles]({{< relref "/docs/setup/install/profiles.md" >}}).

## Enable `syncClusters`

You can use `syncClusters` to synchronize cluster registration across Verrazzano, including in Verrazzano managed cluster resources, Rancher, and Argo CD.

The following illustrates an admin cluster Verrazzano resource that has been configured to use `syncClusters`.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: admin
spec:
  profile: prod
  components:
    clusterOperator:
      overrides:
      - values:
          syncClusters:
            enabled: true
```

</div>
{{< /clipboard >}}

- If `enabled` is set to `false` (the default), then all the Rancher clusters will not be synchronized.
- If `enabled` is set to `true`, then all the Rancher clusters will be automatically synchronized across Verrazzano.

## Set a label selector

In addition, in the Verrazzano resource, you can provide a label selector. The label selector is used to specify which clusters created in Rancher will be automatically registered by Verrazzano.

The following illustrates an admin cluster Verrazzano resource that has been configured to support cluster label selection.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: admin
spec:
  profile: prod
  components:
    clusterOperator:
      overrides:
      - values:
          syncClusters:
            enabled: true
            clusterSelector:
              matchExpressions:
              - key: verrazzanomulticluster
                operator: In
                values: [supported]
```

</div>
{{< /clipboard >}}

- If `enabled` is set to `false` (the default), then no clusters created in Rancher will be automatically registered by Verrazzano.
- If `enabled` is explicitly set to `true`, then Verrazzano will automatically register clusters created in Rancher with labels that match the `clusterSelector` field.
  - The `clusterSelector` field is optional. If it is omitted, then all clusters created in Rancher will be automatically registered.
  - The `clusterSelector` field implements a [LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/{{<kubernetes_api_version>}}/#labelselector-v1-meta).

**NOTE**: If Argo CD is enabled in Verrazzano, then the label selector also is used by Verrazzano to select the Rancher clusters to automatically register with Argo CD. For more information about using Argo CD with Verrazzano, see [Argo CD]({{< relref "/docs/samples/argo-cd/_index.md" >}}).  

## Register managed clusters using the Verrazzano console

Verrazzano will manage all clusters whose labels match the cluster label selector, including Argo CD, if it is enabled on the admin cluster.

To register a cluster, complete the following steps:
1. On the admin cluster, open the Rancher console.
<br>You can find the Rancher console URL for your cluster by following the instructions [here]({{< relref "/docs/access/_index.md#get-the-consoles-urls" >}}).
2. Select **Cluster Management**, and then click **Import Existing Cluster**.
3. Provide a name for your managed cluster, for example, _managed1_.
4. In your Verrazzano configuration, if you specified a cluster label selector, then under **Labels & Annotations** provide a `label` and `value` for the cluster.
<br>For the Verrazzano synchronization to occur automatically, the `label` and `value` information should match the cluster selection `matchExpression` in your Verrazzano configuration.
5. After the import is complete, follow the on-screen instructions to complete the registration by running the provided command against the managed cluster.

After the cluster reaches the `Active` state in the console, synchronization with Verrazzano will happen automatically and a VerrazzanoManagedCluster resource will be created in the `verrazzano-mc` namespace.

Run the following command to view the details and status of Verrazzano's multicluster initialization operations:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get vmc -n verrazzano-mc <Rancher_cluster_name> -o yaml
```

</div>
{{< /clipboard >}}

For more information, see [Registering Existing Clusters](https://ranchermanager.docs.rancher.com/{{<rancher_doc_version>}}/how-to-guides/new-user-guides/kubernetes-clusters-in-rancher-setup/register-existing-clusters) in the Rancher documentation.

**NOTE**: You can also register managed clusters using kubectl, see [Register Managed Clusters using kubectl]({{< relref "/docs/applications/multicluster/register-kubectl.md" >}}).


## Next steps

- Verify your multicluster Verrazzano environment set up by following the instructions at [Verify Multicluster Installation]({{< relref "/docs/setup/install/mc-install/verify-install.md" >}}).
- Deploy multicluster example applications. See [Examples of using Verrazzano in a multicluster environment]({{< relref "/docs/samples/multicluster/_index.md" >}}).

{{< alert title="NOTE" color="primary" >}}
To deregister a managed cluster, see [Deregister a Managed Cluster]({{< relref "/docs/setup/install/mc-install/deregister-install.md" >}}).
{{< /alert >}}
