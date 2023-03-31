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

You can use `syncClusters` to synchronize cluster registrations across Verrazzano, including in the Verrazzano managed cluster resources, in Rancher, and in Argo CD.

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

**NOTE**: To customize which clusters you can select for synchronization, see [Customize Cluster Selection]({{< relref "/docs/applications\multicluster\customize-cluster.md" >}}).

## Register the managed cluster

Verrazzano will manage all clusters whose labels match the cluster label selector, including Argo CD, if it is enabled on the admin cluster.

To register a cluster, complete the following steps:
1. Open the Rancher console on the admin cluster.
<br>You can find the Rancher console URL for your cluster by following the instructions for [Accessing Verrazzano]({{< relref "/docs/access/_index.md" >}}).
2. Select **Cluster Management**, and then click **Import Existing Cluster**.
3. Provide a name for your managed cluster. For example: _managed1_.
4. In your Verrazzano configuration, if you specified a cluster selection label, then under **Labels & Annotations** provide a `label` and `value` for the cluster.
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

**NOTE**: You can also register the managed clusters using kubectl, see [Register Managed Clusters using kubectl]({{< relref "/docs/applications\multicluster\register-kubectl.md" >}}).


## Next steps

- Verify your multicluster Verrazzano environment set up by following the instructions at [Verify Multicluster Installation]({{< relref "/docs/setup/install/mc-install/verify-install.md" >}}).
- Deploy multicluster example applications. See [Examples of using Verrazzano in a multicluster environment]({{< relref "/docs/samples/multicluster/_index.md" >}}).

{{< alert title="NOTE" color="primary" >}}
To deregister a managed cluster, see [Deregister a Managed Cluster]({{< relref "/docs/setup/install/mc-install/deregister-install.md" >}}).
{{< /alert >}}
