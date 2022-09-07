---
title: "Node Failure Guide"
linkTitle: "Node Failure"
description: "A guide for managing node failure"
weight: 1
draft: false
---

## Overview
Unplanned `Node` failure can happen for many reasons including hardware failures or network outages. It is important to
understand what to expect when a `Node` failure happens. This guide will also cover what to know about recovery. Recovery
is dependent upon the `Storage Provisioner` and type of storage used. This guide assumes the storage provided in the cluster is physically
separate from the `Node` and is recoverable. It does not apply to local storage on the `Node` itself.

## What to expect
By default, when a `Node` fails it takes 1 minute for that failure to result in the Kubernetes API server returning the `Node's` status as
`NotReady`. Approximately 5 minutes after the `Node's` status returns `NotReady`, `Pods` on that `Node` will begin to change status to `Unknown`
or `NodeLost`. `Pods` with a controller like `Daemonsets`, `Statefulsets`, and `Deployments` will transition to a status of `Terminating`.
New `Pods` will begin to start on `Node's` with a status of `Ready`. `Pods` without a controller, started with just a `PodSpec`, will not be terminated.
They must me manually managed.

`Pods` with associated `Persistent Volumes` of mode `ReadWriteOnce` will not become `Ready` because they will attempt to attach to existing volumes
that are still attached to the old `Pod` stuck in status `Terminating`. This is because `Persistent Volumes` of mode `ReadWriteOnce` can only
be mounted by a single `Pod` at a time.

If multiple `Availability Domains` are used in the Kubernetes cluster, if the failed `Node` is the last in that `Availability Domain`,
the existing volumes will no longer be reachable by new `Pods` in a separate `Availability Domain`.

## What to know about recovery
If the `Node` can be recovered within 5-6 minutes then `Pods` will return to a `Running` state. If the `Node` can be recovered after 5-6 minutes,
then `Pods` will complete termination and be deleted from the Kubernetes API server. New `Pods` that have `Persistent Volumes` of mode `ReadWriteOnce`
will now be able to mount those `Persistent Volumes` and come to a `Running` state. 

If the `Node` cannot be recovered and will instead be replaced, deleting the `Node` from the Kubernetes API server will complete the termination
of the old `Pods` and release the `Persistent Volumes` of type `ReadWriteOnce` to be mounted by the new `Pods`. 

If multiple `Avaiability Domains` are used in the Kubernetes cluster, then the replacement `Node` should be added to the same `Availability Domain`
that the deleted `Node` occupied. This will allow `Pods` to be scheduled on the replacement `Node` that can reach the `Persistent Volumes` in that
`Availability Domain` and those `Pods` to come to a `Running` state.

Forced deletes of `Pods` and `Persistent Volumes` for a `Node` to be recovered or replaced is strongly discouraged. This can lead to loss of data and in the case
of `Statefulsets` lead to split-brain scenarios. Please read more about statefulsets in the [offical Kubernetes documentation](https://kubernetes.io/docs/tasks/run-application/force-delete-stateful-set-pod/).
One instance of needing to force delete `Pods` and `Persistent Volumes` is when a `Node` cannot be recovered or replaced in the same `Availability Domain` as
the original `Node`.