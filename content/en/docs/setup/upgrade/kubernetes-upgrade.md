---
title: "Upgrade Kubernetes with Verrazzano installed"
description: ""
weight: 8
draft: false
---

After Verrazzano is installed in a cluster, you may want to upgrade the Kubernetes version of that cluster.
For information on the Kubernetes versions that Verrazzano supports, see the [Prerequisites]({{< relref "/docs/setup/install/prepare/prereqs.md#kubernetes" >}}).

The following lists documentation sources for Kubernetes cluster updates.
If yours does not appear on this list, then consult your cluster provider's upgrade documentation.
- [OKE Kubernetes Upgrade](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengupgradingk8smasternode.htm)
- [OCNE Kubernetes Upgrade](https://docs.oracle.com/en/operating-systems/olcne/1.5/upgrade/update.html#update)
- [kubeadm Kubernetes Upgrade](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/)

## Upgrade a multinode cluster

For a typical multinode Kubernetes cluster, we recommend keeping one or more nodes present and available while upgrading nodes.
This allows the cordoned nodes to distribute the pods to available nodes, which eliminates downtime during an upgrade.
Your cluster provider can provide information on maintaining node availability for an in-place upgrade.

## Upgrade a single-node cluster

For a single-node cluster upgrade, there will be downtime in the cluster to allow the node to cordon while it is upgraded.
For this reason, there are a few manual workaround steps that you may need to perform to be able to fully drain the Kubernetes node.

### Disable the MySQL pod disruption budget
The MySQL Operator deploys a [Pod Disruption Budget](https://kubernetes.io/docs/concepts/workloads/pods/disruptions/#pod-disruption-budgets)
for the MySQL database pods.
This Pod Disruption Budget will prevent the node from being drained.
To change this, you can patch the Pod Disruption budget to allow the MySQL replicas to be drained from the node.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl patch poddisruptionbudgets.policy -n keycloak mysql-pdb -p '{"spec":{"minAvailable":0, "maxUnavailable":null}}' --type=merge
```

</div>
{{< /clipboard >}}

### Remove the MySQL pod finalizers
It is possible that the MySQL pods will be stuck in the `Terminating` state while the node is being drained.
If you find that the MySQL pod will not complete termination, then you can remove the finalizers to manually terminate these pods.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl patch pod -n keycloak mysql-0 -p '{"metadata":{"finalizers":null}}' --type=merge
```

</div>
{{< /clipboard >}}

### Delete the Rancher Helm pods
Rancher spins up Helm pods for cluster operations.
Because these pods are not managed by any parent resources, they can prevent the node from being drained.
If this is the case, then you can delete these pods with the following command.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl get pods --no-headers=true -n cattle-system | awk '{print $1}' | grep helm | xargs kubectl delete pod --ignore-not-found -n cattle-system
```

</div>
{{< /clipboard >}}
