---
title: "Troubleshoot Multicluster Setup Issues"
description: "Troubleshoot issues with multicluster setup and applications"
weight: 6
draft: false
aliases:
  - /docs/troubleshooting/troubleshooting-multicluster
---

This document describes some common problems you might encounter when using multicluster Verrazzano, and how to troubleshoot them.

If you created multicluster resources in the admin cluster, and specified a `placement` value in a managed cluster,
then those resources will get created in that managed cluster. If they do not get created in the managed cluster, then
use the following steps to troubleshoot:
- Verify that the managed cluster is registered correctly and can connect to the admin cluster.
- Verify that the VerrazzanoProject for the resource's namespace, also has a `placement` in that managed cluster.
- Check the multicluster resource's status field on the admin cluster to know what the status of that resource is
  on each managed cluster to which it is targeted.

If you update the [DNS]({{< relref "/docs/networking/traffic/dns" >}}) of the admin cluster and notice that the
managed cluster status is unavailable in the Rancher console, along with the error `x509: certificate is valid for
<rancher new url>, not <rancher old url>` seen in the `cattle-cluster-agent` (Rancher Agent) logs on the
managed cluster, then re-register the managed cluster, as described [here](#re-register-the-managed-cluster).

## Verify managed cluster registration and connectivity
You can verify that a managed cluster was successfully registered with an admin cluster by viewing the
corresponding VerrazzanoManagedCluster (VMC) resource on the admin cluster. For example, to verify that a managed cluster
named `managed1` was successfully registered:
{{< clipboard >}}
<div class="highlight">

```
# on the admin cluster
$ kubectl get verrazzanomanagedcluster managed1 \
    -n verrazzano-mc \
    -o yaml
```

</div>
{{< /clipboard >}}

Partial sample output from the previous command.
{{< clipboard >}}
<div class="highlight">

```
  status:
    conditions:
    - lastTransitionTime: "2021-06-22T21:03:27Z"
      message: Ready
      status: "True"
      type: Ready
    lastAgentConnectTime: "2021-06-22T21:06:04Z"
    ... other fields ...
```

</div>
{{< /clipboard >}}

Check the `lastAgentConnectTime` in the status of the VMC resource. This is the last time at which the
managed cluster connected to the admin cluster. If this value is not present, or is not recent (within the last
three minutes), then the managed cluster named `managed1` cannot successfully connect to the admin cluster.
This could be due to several reasons:

* The managed cluster registration process step of applying the registration YAML on the managed cluster,
was not completed. For the complete setup instructions, see [here]({{< relref "/docs/setup/mc-install/multicluster#register-the-managed-cluster" >}}).

* The managed cluster does not have network connectivity to the admin cluster. The managed cluster will attempt to
connect to the admin cluster at regular intervals, and any errors will be reported in the
`verrazzano-application-operator` pod's log on the _managed_ cluster. View the logs using the following command:
{{< clipboard >}}
<div class="highlight">

```
# on the managed cluster
$ kubectl logs \
    -n verrazzano-system \
    -l app=verrazzano-application-operator
```

</div>
{{< /clipboard >}}

If these logs reveal that there is a connectivity issue, then in the case of an installation that includes Rancher on
the admin cluster, there may have been a problem with Verrazzano pushing registration details or updates to the managed
cluster. Try exporting and applying the registration manifest to the managed cluster as shown:
{{< clipboard >}}
<div class="highlight">

  ```
  # on the admin cluster
       kubectl get secret \
       -n verrazzano-mc verrazzano-cluster-managed1-manifest \
       -o jsonpath={.data.yaml} | base64 --decode > register.yaml

  # on the managed cluster
       kubectl apply -f register.yaml
  ```

</div>
{{< /clipboard >}}

**NOTE**: If your installation disabled Rancher on the admin cluster, then check the admin cluster Kubernetes server
address that you provided during registration and ensure that it is correct, and that it is reachable from the managed
cluster. If it is incorrect, then you will need to repeat the managed cluster registration process described in the setup instructions
[here]({{< relref "/docs/setup/mc-install/multicluster#register-the-managed-cluster" >}}).


## Verify VerrazzanoProject placement
For Verrazzano to create an application namespace in a managed cluster, that namespace must be part of a VerrazzanoProject
that:

* Includes that namespace.
* Has a `placement` value that includes that managed cluster.

View the details of the project that corresponds to your application's namespace. In the example command that follows, the
project name is assumed to be `myproject`. All projects are expected to be created in the `verrazzano-mc` namespace.
{{< clipboard >}}
<div class="highlight">

```
# on the admin cluster
$ kubectl get verrazzanoproject myproject \
    -n verrazzano-mc \
    -o yaml
```

</div>
{{< /clipboard >}}


The following partial sample output is for a project that will result in the namespace `mynamespace` being created on the managed
cluster `managed1`.
{{< clipboard >}}
<div class="highlight">

```
spec:
  placement:
    clusters:
    - name: managed1
  template:
    namespaces:
    - metadata:
        name: mynamespace
....other fields....
```

</div>
{{< /clipboard >}}

## Check the multicluster resource status
On the admin cluster, each multicluster resource's status field is updated with the status of the underlying resource
on each managed cluster in which it is placed.

The following example command shows how to view the status of a MultiClusterApplicationConfiguration named `myapp`, in
the namespace `mynamespace`, that has a `placement` value that includes the managed cluster `managed1`.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get multiclusterapplicationconfiguration myapp \
    -n mynamespace \
    -o yaml
```

</div>
{{< /clipboard >}}


The status of the underlying resource in each cluster specified in the placement is shown in the following partial sample
output.
{{< clipboard >}}
<div class="highlight">

```
  status:
    clusters:
    - lastUpdateTime: "2021-06-22T21:05:04Z"
      message: OAM Application Configuration created
      name: managed1
      state: Succeeded
    conditions:
    - lastTransitionTime: "2021-06-22T21:03:58Z"
      message: OAM Application Configuration created
      status: "True"
      type: DeployComplete
    state: Succeeded
```

</div>
{{< /clipboard >}}

The status message contains additional information on the operation's success or failure.

## Re-register the managed cluster
Perform the following steps to re-register the managed cluster with the admin cluster. The cluster against which to run
the command is indicated in each code block.
1. On the admin cluster, export the register YAML file newly created on the admin cluster to re-register the
   managed cluster.
{{< clipboard >}}
<div class="highlight">

   ```
   # On the admin cluster
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
       get secret verrazzano-cluster-managed1-manifest \
       -n verrazzano-mc \
       -o jsonpath={.data.yaml} | base64 --decode > register_new.yaml
   ```

</div>
{{< /clipboard >}}

2. On the managed cluster, apply the registration file exported in the previous step.
{{< clipboard >}}
<div class="highlight">

   ```
   # On the managed cluster
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 --context $KUBECONTEXT_MANAGED1 \
       apply -f register_new.yaml

   # After the command succeeds, you may delete the register_new.yaml file
   $ rm register_new.yaml
   ```

</div>
{{< /clipboard >}}

3. On the admin cluster, run `kubectl patch clusters.management.cattle.io` to trigger redeployment of the Rancher agent
   on the managed cluster.
{{< clipboard >}}
<div class="highlight">

   ```
   # On the admin cluster
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
       get clusters.management.cattle.io

   # Sample output
   NAME      AGE
   c-mzb2h   4h48m
   local     4h56m

   $ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
       patch clusters.management.cattle.io <the managed cluster name from the above output> \
       -p '{"status":{"agentImage":"dummy"}}' --type merge

   # Sample output
   cluster.management.cattle.io/c-mzb2h patched
   ```

</div>
{{< /clipboard >}}
