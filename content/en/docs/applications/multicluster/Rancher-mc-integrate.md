---
title: "Use Rancher for Multicluster Verrazzano"
description: "Use Rancher to set up a multicluster environment"
weight: 2
draft: false
---

Multicluster Verrazzano provides integration with Rancher that allows automatic synchronization of Rancher clusters with Verrazzano managed clusters, which simplifies your managed cluster registration process. By configuring cluster label selection, you can customize your Verrazzano installation to perform this automatic synchronization.

## Step 1: Enable cluster label selection in Verrazzano

You can provide a label selector in the Verrazzano resource. The label selector is used to determine which clusters created in Rancher will be automatically registered by Verrazzano.

**NOTE**: If Argo CD is enabled in Verrazzano, then the label selector also is used by Verrazzano to select the Rancher clusters to automatically register with Argo CD. For more information about using Argo CD with Verrazzano, see [Argo CD]({{< relref "/docs/samples/argo-cd/_index.md" >}}).

### Verrazzano configuration for cluster label selection

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


## Step 2: Register managed cluster from Rancher console

Verrazzano will manage all clusters whose labels match the [cluster label selector](#cluster-label-selection), including Argo CD, if it is enabled on the admin cluster.

To register a cluster using Rancher, complete the following steps:
1. Open the Rancher console on the admin cluster.
<br>You can find the Rancher console URL for your cluster by following the instructions for [Accessing Verrazzano]({{< relref "/docs/access/_index.md" >}}).
2. Select **Cluster Management**, and then click **Import Existing Cluster**.
3. Provide a name for your managed cluster. For example: _managed1_.
4. In your Verrazzano configuration, if you specified a cluster selection label, then under **Labels & Annotations** provide a `label` and `value` for the Rancher cluster.
<br>For the Verrazzano synchronization to occur automatically, the `label` and `value` information should match the cluster selection `matchExpression` in your Verrazzano configuration.
5. After the import is complete, follow Rancher's on-screen instructions to complete the registration by running the provided command against the managed cluster.

After the Rancher cluster reaches the `Active` state in the Rancher console, synchronization with Verrazzano will happen automatically and a VerrazzanoManagedCluster resource will be created in the `verrazzano-mc` namespace.

Run the following command to view the details and status of Verrazzano's multicluster initialization operations:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get vmc -n verrazzano-mc <Rancher_cluster_name> -o yaml
```

</div>
{{< /clipboard >}}

For more information, see [Registering Existing Clusters](https://ranchermanager.docs.rancher.com/{{<rancher_doc_version>}}/how-to-guides/new-user-guides/kubernetes-clusters-in-rancher-setup/register-existing-clusters) in the Rancher documentation.
