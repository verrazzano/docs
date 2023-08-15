---
title: "Upgrade Kubernetes with Verrazzano"
description: "Upgrade the Kubernetes version with a Verrazzano installation"
weight: 8
draft: false
---

After Verrazzano is installed onto a cluster, you may want to upgrade the Kubernetes version of that cluster.
The following list links to documentation sources for Kubernetes cluster updates.
Consult your cluster provider's upgrade documentation if it does not appear on this list.
- [OKE Kubernetes Upgrade](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengupgradingk8smasternode.htm).
- [OLCNE Kubernetes Upgrade](https://docs.oracle.com/en/operating-systems/olcne/1.5/upgrade/update.html#update).
- [kubeadm Kubernetes Upgrade](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/).

## Upgrading a multi-node cluster

For a typical multi-node Kubernetes cluster, it is recommended to keep one or more nodes present and available while upgrading nodes.
This allows the cordoned nodes to distribute the pods to available nodes to eliminate downtime during an upgrade.
Your cluster provider should have information on maintaining node availability for an in-place upgrade.

## Upgrading a single node cluster

For a single node cluster upgrade, there will be downtime in the cluster to allow the node to cordon while it is upgraded.
For this reason, there are a few manual workarounds that may need be done to be able to fully drain the Kubernetes node.

### Disable the MySQL pod disruption budget
The MySQL Operator deploys a [Pod Disruption Budget](https://kubernetes.io/docs/concepts/workloads/pods/disruptions/#pod-disruption-budgets)
for the MySQL database pods. 
This Pod Disruption Budget will prevent the node from being drained.
To prevent this, you can patch the Pod Disruption budget to allow the MySQL replicas to be drained from the node.

```shell
kubectl patch poddisruptionbudgets.policy -n keycloak mysql-pdb -p '{"spec":{"minAvailable":0, "maxUnavailable":null}}' --type=merge
```

### Remove the MySQL pod finalizers
It is possible that the MySQL pods will be stuck in the `Terminating` state while the node is being drained.
If you find that the MySQL pod will not complete termination, you can remove the finalizers to manually terminate these pods.

```shell
kubectl patch pod -n keycloak mysql-0 -p '{"metadata":{"finalizers":null}}' --type=merge
```

