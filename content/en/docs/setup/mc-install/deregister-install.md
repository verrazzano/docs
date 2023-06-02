---
title: "Deregister a Managed cluster"
description: "Deregister managed clusters in your multicluster Verrazzano environment"
weight: 3
draft: false
aliases:
  - /docs/setup/install/mc-install/deregister-install
---

**NOTE**: The following procedure is for a cluster in which Rancher is enabled on the admin cluster. If Rancher is not enabled, then additional steps are required to deregister a managed cluster, see [Deregister a managed cluster without Rancher]({{< relref "docs/setup/mc-install/advanced-mc-install.md#deregister-a-managed-cluster-without-rancher" >}}).

If you want to deregister a managed cluster because you no longer want it to be part of a Verrazzano multicluster
environment, then  log in to the Rancher console and delete the managed cluster. To delete a cluster in Rancher, see
[What if I don't want my registered cluster managed by Rancher?](https://ranchermanager.docs.rancher.com/{{<rancher_doc_version>}}/faq/rancher-is-no-longer-needed#what-if-i-dont-want-my-registered-cluster-managed-by-rancher)
This results in the cluster being deregistered from Verrazzano. The associated `VerrazzanoManagedCluster` resource
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
