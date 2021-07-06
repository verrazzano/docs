---
title: "Troubleshooting Multicluster Verrazzano"
linkTitle: "Multicluster"
description: "Troubleshooting problems with multicluster setup and applications"
weight: 1
draft: false
---

This document describes some common problems you may encounter when using multicluster Verrazzano, and how to troubleshoot them.

If you created multicluster resources in the admin cluster, and specified a `placement` value in a managed cluster,
then those resources will get created in that managed cluster. If they do not get created in the managed cluster, then
use the following steps to troubleshoot:
- Verify that the managed cluster is registered correctly and can connect to the admin cluster.
- Verify that the VerrazzanoProject for the resource's namespace, also has a `placement` in that managed cluster.
- Check the multicluster resource's status field on the admin cluster to know what the status of that resource is
  on each managed cluster to which it is targeted.

## Verify managed cluster registration and connectivity
You can verify that a managed cluster was successfully registered with an admin cluster by viewing the
corresponding VerrazzanoManagedCluster (VMC) resource on the admin cluster. For example, to verify that a managed cluster
named `managed1` was successfully registered:
```shell
# on the admin cluster
$ kubectl get verrazzanomanagedcluster managed1 -n verrazzano-mc -o yaml
```

Partial sample output from the previous command:
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

Check the `lastAgentConnectTime` in the status of the VMC resource. This is the last time at which the
managed cluster connected to the admin cluster. If this value is not present, then the managed cluster named `managed1`
never successfully connected to the admin cluster. This could be due to several reasons:

1. The managed cluster registration process step of applying the registration YAML on the managed cluster,
was not completed. For the complete setup instructions, see [here]({{< relref "/docs/setup/install/multicluster" >}}).

1. The managed cluster does not have network connectivity to the admin cluster. The managed cluster will attempt to
connect to the admin cluster at regular intervals, and any errors will be reported in the
`verrazzano-application-operator` pod's log on the _managed_ cluster. View the logs using the following command.

```shell
# on the managed cluster
$ kubectl logs -n verrazzano-system -l app=verrazzano-application-operator
```
If these logs reveal that there is a connectivity issue, check the admin cluster Kubernetes server address that
you provided during registration and ensure that it is correct, and that it is reachable from the managed cluster. If it
is incorrect, then you will need to repeat the managed cluster registration process described in the setup instructions
[here]({{< relref "/docs/setup/install/multicluster" >}}).

## Verify VerrazzanoProject placement
For Verrazzano to create an application namespace in a managed cluster, that namespace must be part of a VerrazzanoProject
that:

1. Includes that namespace.
1. Has a `placement` value that includes that managed cluster.

View the details of the project that corresponds to your application's namespace. In the example command that follows, the
project name is assumed to be `myproject`. All projects are expected to be created in the `verrazzano-mc` namespace.

```shell
# on the admin cluster
$ kubectl get verrazzanoproject myproject -n verrazzano-mc -o yaml
```

The following partial sample output is for a project that will result in the namespace `mynamespace` being created on the managed
cluster `managed1`.

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

## Check the multicluster resource status
On the admin cluster, each multicluster resource's status field is updated with the status of the underlying resource
on each managed cluster in which it is placed.

The following example command shows how to view the status of a MultiClusterApplicationConfiguration named `myapp`, in
the namespace `mynamespace`, that has a `placement` value that includes the managed cluster `managed1`
```shell
$ kubectl get multiclusterapplicationconfiguration myapp -n mynamespace -o yaml
```

The status of the underlying resource in each cluster specified in the placement is shown in the following partial sample
output:

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

The status message contains additional information on the operation's success or failure.
