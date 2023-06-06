---
title: "MySQL Issues"
description: "Troubleshoot MySQL issues"
weight: 4
draft: false
---

There are known issues that can occur with MySQL.  The Verrazzano platform operator will automatically detect each of the described issues and perform actions to repair them.  The operator initiates a repair within a few minutes of detecting an issue.  

The following sections are provided in the event that a manual repair of an issue is required.

### MySQL pod stuck Terminating
A MySQL pod may get stuck in a terminating state.  This may occur while upgrading the nodes of a Kubernetes cluster.

Here is an example of what this condition looks like.  All the pod containers are terminated, but the pod never finishes terminating.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get pods -n keycloak -l component=mysqld
NAME      READY   STATUS        RESTARTS   AGE
mysql-0   0/3     Terminating   0          60m
```
{{< /clipboard >}}
</div>


You can repair this issue by restarting the `mysql-operator` pod.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl delete pod -l name=mysql-operator -n mysql-operator
```
{{< /clipboard >}}
</div>


### MySQL pod waiting for readiness gates
The `mysql` StatefulSet may get stuck while waiting to reach the ready state.  This will occur when one or more MySQL pods not meeting its set of `ReadinessGates`.

Here is an example of what this condition looks like.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl describe pods -n keycloak -l component=mysqld
```
```
# Excerpt from the command output
Readiness Gates:
  Type                          Status
  mysql.oracle.com/configured   False
  mysql.oracle.com/ready        True
```
{{< /clipboard >}}
</div>

You can repair this issue by restarting the `mysql-operator` pod.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl delete pod -l name=mysql-operator -n mysql-operator
```
{{< /clipboard >}}
</div>

### MySQL router pod in CrashLoopBackOff state

Here is an example of what this condition looks like.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get pods -n keycloak -l component=mysqlrouter
NAME                            READY   STATUS             RESTARTS   AGE
mysql-router-757595f6c5-pdgxj   1/2     CrashLoopBackOff   0          109m
```
{{< /clipboard >}}
</div>

You can repair this issue by deleting the pod that is in the `CrashLoopBackOff` state.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl delete pod -n keycloak mysql-router-757595f6c5-pdgxj
```
{{< /clipboard >}}
</div>

### InnoDBCluster object stuck Terminating
This condition has been observed to occur on an uninstallation of Verrazzano.

Here is an example of what this condition looks like.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get InnoDBCluster -n keycloak
NAME    STATUS    ONLINE   INSTANCES   ROUTERS   AGE
mysql   OFFLINE   0        1           1         7m51s
```
{{< /clipboard >}}
</div>

You can repair this issue by restarting the `mysql-operator` pod.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl delete pod -l name=mysql-operator -n mysql-operator
```
{{< /clipboard >}}
</div>
