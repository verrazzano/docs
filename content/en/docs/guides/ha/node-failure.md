---
title: "Node Failure Guide"
linkTitle: "Node Failure"
description: "A guide for managing node failure"
weight: 1
draft: false
---

## Overview
Unplanned node failure can happen for many reasons including hardware failures or network outages. It is important to
understand what to expect when a node failure happens. This guide will also cover what to know about recovery. Recovery
is dependent upon the storage provisioner and type of storage used. This guide assumes the storage provided in the cluster is physically
separate from the node and is recoverable. It does not apply to local storage on the node itself.

## What to expect
By default, when a node fails it takes 1 minute for that failure to result in the Kubernetes API server returning the node's status as
NotReady. Approximately 5 minutes after the node's status returns NotReady, Pods on that node will begin to change status to Unknown
or NodeLost. Pods with with a controller like `Daemonsets`, `Statefulsets`, and `Deployments` will transition to a status of Terminating.
New pods will begin to start on node's with a status of Ready. Pods without a controller, started with just a `PodSpec`, will not be terminated.
They must me manually managed.

Pods with associated persistent volumes of mode `ReadWriteOnce` will not become Ready because they will attempt to attach to existing volumes
that are still attached to the old pod stuck in status Terminating. This is because persistent volumes of mode `ReadWriteOnce` can only
be mounted by a single pod at a time.

If multiple availability domains are used in the Kubernetes cluster, if the failed node is the last in that availability domain,
the existing volumes will no longer be reachable by new pods in a separate availability domain.

## What to know about recovery
If the node can be recovered within 5-6 minutes then pods will return to a running state. If the node can be recovered after 5-6 minutes,
then pods will complete termination and be deleted from the Kubernetes API server. New pods that have persistent volumes of mode `ReadWriteOnce`
will now be able to mount the persistent volumes and come to a running state. 

If the node cannot be recovered and will instead be replaced, deleting the node from the Kubernetes API server will complete the termination
of the old pods and release the persistent volumes of type `ReadWriteOnce` to be mounted by the new pods. 

If multiple avaiability domains are used in the Kubernetes cluster, then the replacement node should be added to the same availability domain
that the deleted node occupied. This will allow pods to be scheduled on the replacement node that can reach the persistent volumes in that
availability domain and those pods to come to a running state.

Forced deletes of pods and volumes for a node to be recovered or replaced is strongly discouraged. This can lead to loss of data and in the case
of `Statefulsets` lead to split-brain scenarios. Please read more about statefulsets in the [offical Kubernetes documentation](https://kubernetes.io/docs/tasks/run-application/force-delete-stateful-set-pod/).