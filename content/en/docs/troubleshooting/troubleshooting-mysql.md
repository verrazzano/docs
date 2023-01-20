---
title: "MySQL"
linkTitle: "MySQL"
description: "Troubleshoot MySQL issues"
weight: 5
draft: false
---

There are known issues that can occur with `MySQL`.  The `verrazzano-platform-operator` automatically detects each of the issues described below and performs the actions to repair them.  The `verrazzano-platform-operator` will initiate a repair within a few minutes of an issue being detected.  

The following sections are provided in the event that a manual repair of an issue is required.

### MySQL pod stuck `Terminating`
A `MySQL` pod may get stuck in a terminating state.  One possible cause is while upgrading the nodes of a Kubernetes cluster.

This is an example of what this condition looks like.  All the pod containers are terminated, but the pod never finishes terminating.
```
$ kubectl get pods -n keycloak -l component=mysqld
NAME      READY   STATUS        RESTARTS   AGE
mysql-0   0/3     Terminating   0          60m
```

The action to repair this issue is to restart the `mysql-operator` pod.
```
$ kubectl delete pod -l name=mysql-operator -n mysql-operator
```

### MySQL pod waiting for readiness gates
The `mysql` StatefulSet may get stuck waiting to reach the ready state.  This can be caused by one or more MySQL pods not meeting its set of `ReadinessGates`.

This is an example of what this condition looks like.
```
$ kubectl describe pods -n keycloak -l component=mysqld

# Excerpt from the command output
Readiness Gates:
  Type                          Status
  mysql.oracle.com/configured   False 
  mysql.oracle.com/ready        True 
```

The action to repair this issue is to restart the `mysql-operator` pod.
```
$ kubectl delete pod -l name=mysql-operator -n mysql-operator
```

### MySQL router pod in `CrashLoopBackOff` state

This is an example of what this condition looks like.
```
$ kubectl get pods -n keycloak -l component=mysqlrouter
NAME                            READY   STATUS             RESTARTS   AGE
mysql-router-757595f6c5-pdgxj   1/2     CrashLoopBackOff   0          109m
```

The action to repair this issue is to delete the pod that is in the `CrashLoopBackOff` state.
```
$ kubectl delete pod -n keycloak mysql-router-757595f6c5-pdgxj
```

### InnoDBCluster object stuck `Terminating`
This condition has been observed to occur on an uninstallation of Verrazzano.

This is an example of what this condition looks like.
```
$ kubectl get InnoDBCluster -n keycloak
NAME    STATUS    ONLINE   INSTANCES   ROUTERS   AGE
mysql   OFFLINE   0        1           1         7m51s
```

The action to repair this issue is to restart the `mysql-operator` pod.
```
$ kubectl delete pod -l name=mysql-operator -n mysql-operator
```
