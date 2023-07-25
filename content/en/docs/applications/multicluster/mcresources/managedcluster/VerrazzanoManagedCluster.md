---
title: VerrazzanoManagedCluster
linkTitle: "VerrazzanoManagedCluster"
weight: 4
draft: false
---

The [VerrazzanoManagedCluster]({{< relref "/docs/reference/vco-clusters-v1alpha1#clusters.verrazzano.io/v1alpha1.VerrazzanoManagedCluster" >}}) custom resource is used to register a managed cluster with an admin cluster.  Here is a sample VerrazzanoManagedCluster that registers the cluster named `managed1`.  To deploy an example application that demonstrates a VerrazzanoManagedCluster, see [Multicluster Hello World Helidon]({{< relref "/docs/examples/multicluster/hello-helidon/" >}}).
{{< clipboard >}}
<div class="highlight">

    apiVersion: clusters.verrazzano.io/v1alpha1
    kind: VerrazzanoManagedCluster
    metadata:
      name: managed1
      namespace: verrazzano-mc
    spec:
      description: "Managed Cluster 1"
      caSecret: ca-secret-managed1

</div>
{{< /clipboard >}}
