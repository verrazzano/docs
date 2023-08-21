---
title: "Use the Verrazzano Console"
description: "Register managed clusters using the Verrazzano console"
weight: 1
draft: false
---

To register a cluster, complete the following steps:
1. Enable `syncClusters`.
<br>For information about `syncClusters`, see [Enable syncClusters]({{< relref "/docs/setup/mc-install/register/syncclusters#enable-syncclusters" >}}).
{{< clipboard >}}
<div class="highlight">

```
kubectl apply -f - <<EOF
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
EOF
```

</div>
{{< /clipboard >}}

2. On the admin cluster, open the Rancher console.
<br>You can find the Rancher console URL for your cluster by following the instructions [here]({{< relref "/docs/setup/access/_index.md#get-the-consoles-urls" >}}).
2. Select **Cluster Management**, and then click **Import Existing Cluster**.
3. Provide a name for your managed cluster, for example, _managed1_.
4. Optional. In your Verrazzano configuration, if you specified a [cluster label selector]({{< relref "/docs/setup/mc-install/register/syncclusters#filter-cluster-selection" >}}), then under **Labels & Annotations** provide the `label` and `value` for the cluster. The `label` and `value` information must match the cluster selection `matchExpression` in your Verrazzano configuration for selective cluster registration to occur.
5. Click **Create**.
6. On the next screen, follow the on-screen instructions to complete the registration by running the provided command against the managed cluster.

After the cluster reaches the `Active` state in the console, synchronization with Verrazzano will happen automatically and a VerrazzanoManagedCluster resource will be created in the `verrazzano-mc` namespace.

Run the following command to view the details and status of Verrazzano's multicluster initialization operations:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get vmc -n verrazzano-mc <Rancher_cluster_name> -o yaml
```

</div>
{{< /clipboard >}}

For more information, see [Registering Existing Clusters](https://ranchermanager.docs.rancher.com/how-to-guides/new-user-guides/kubernetes-clusters-in-rancher-setup/register-existing-clusters) in the Rancher documentation.

**NOTE**: You can also register managed clusters using `kubectl`, see [Register Managed Clusters using kubectl]({{< relref "/docs/setup/mc-install/register/register-kubectl.md" >}}).


## Next steps

- Verify your multicluster Verrazzano environment set up by following the instructions at [Verify Multicluster Installation]({{< relref "/docs/setup/mc-install/verify-install.md" >}}).
- Deploy multicluster example applications. See [Examples of using Verrazzano in a multicluster environment]({{< relref "/docs/examples/multicluster/_index.md" >}}).

{{< alert title="NOTE" color="primary" >}}
To deregister a managed cluster, see [Deregister a Managed Cluster]({{< relref "/docs/setup/mc-install/deregister-install.md" >}}).
{{< /alert >}}
