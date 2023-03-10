---
title: "Multicluster Tasks"
description: "Learn about the tasks that you can perform in a multicluster Verrazzano environment"
weight: 1
draft: false
---


## Run applications in multicluster Verrazzano

The Verrazzano multicluster setup is now complete and you can deploy applications by following the [Multicluster Hello World Helidon]({{< relref "/docs/samples/multicluster/hello-helidon/_index.md" >}}) example application.

## Use the admin cluster UI

The admin cluster serves as a central point from which to register and deploy applications to managed clusters.

In the Verrazzano UI on the admin cluster, you can view the following:

- The managed clusters registered with this admin cluster.
- VerrazzanoProjects located on this admin cluster or any of its registered managed clusters, or both.
- Applications located on this admin cluster or any of its registered managed clusters, or both.

## Deregister a managed cluster

**NOTE**: The following procedure is for a cluster in which Rancher is enabled on the admin cluster. If Rancher is not enabled, then additional steps will be required to deregister a managed cluster, see [Deregister a managed cluster without Rancher]({{< relref "docs/setup/install/mc-install/multicluster-no-rancher.md#deregister-a-managed-cluster-without-rancher" >}}).

If you want to deregister a managed cluster because you no longer want it to be part of a Verrazzano multicluster
environment, then  log in to the Rancher console and delete the managed cluster. To delete a cluster in Rancher, see
[What if I don't want my registered cluster managed by Rancher?](https://ranchermanager.docs.rancher.com/{{<rancher_doc_version>}}/faq/rancher-is-no-longer-needed#what-if-i-dont-want-my-registered-cluster-managed-by-rancher)
This will result in the cluster being deregistered from Verrazzano. The associated `VerrazzanoManagedCluster` resource
will be automatically deleted, and, if present, then the Argo CD registration of the managed cluster also will be removed.

Alternatively, you can deregister a managed cluster by deleting the `VerrazzanoManagedCluster` resource. This will result
in the automatic cleanup of the Rancher cluster, as well as the Argo CD registration, if it is present.
{{< clipboard >}}
<div class="highlight">

   ```
   # On the admin cluster
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
       delete vmc -n verrazzano-mc managed1
   ```

</div>
{{< /clipboard >}}

**NOTE**: Even after deregistration, any applications that you deployed previously to the managed cluster will continue running on that cluster.
