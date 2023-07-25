---
title: "Node Failure Guide"
linkTitle: "Node Failure"
weight: 2
draft: false
---

A `Node` failure can occur for many reasons, including hardware failures and network outages. This guide provides information about what to
expect when a `Node` failure occurs and how to recover from a `Node` failure. Recovery depends on the `Storage Provisioner` and the type of storage that you use.

{{< alert title="NOTE" color="primary" >}}
This guide assumes that the storage provided in the cluster is physically
separate from the `Node` and is recoverable. It does not apply to a local storage on the `Node`.
{{< /alert >}}

## What to expect

By default, when a `Node` fails:  
- It may take up to a minute for the failure to reflect in the Kubernetes API server and update the `Node` status to
`NotReady`.
- After about five minutes of the `Node` status being `NotReady`, the status of the `Pods` on that `Node` will be changed to `Unknown`
or `NodeLost`.
- The status of the `Pods` with controllers, like `Daemonsets`, `Statefulsets`, and `Deployments`, will be changed to `Terminating`.

   **NOTE**: `Pods` without a controller, started with a `PodSpec`, will _not_ be terminated. They must be manually deleted and recreated.

- New `Pods` will start on the `Nodes` that remain with `Ready` status.   

   **NOTE**: `Statefulsets` are a special case. The `Statefulset` controller maintains an ordinal list of `Pods`, one each for a given name. The `Statefulset` controller
   will not start a new `Pod` with the name of an existing `Pod`.

- The `Pods` that have associated `Persistent Volumes` of type `ReadWriteOnce`, do not become `Ready`. This is because the `Pods` try to attach to the existing volumes
   that are still attached to the old `Pod`, which is still `Terminating`. This happens because, at a given point, the `Persistent Volumes` of type `ReadWriteOnce`, can be associated
   only with a _single_ `Node`, and the new `Pod` resides on another `Node`.

- If multiple `Availability Domains` are used in the Kubernetes cluster and the failed `Node` is the last in that `Availability Domain`, then
   the existing volumes will no longer be reachable by new `Pods` in a separate `Availability Domain`.   

## About recovery

After a `Node` fails, if the `Node` can be recovered within five minutes, then the `Pods` will return to a `Running` state. If the `Node` is not recovered after five minutes,
then the `Pods` will complete termination and are deleted from the Kubernetes API server. New `Pods` that have `Persistent Volumes` of type `ReadWriteOnce`,
will now be able to mount the `Persistent Volumes` and change to `Running`.


If a `Node` cannot be recovered and is replaced, then deleting the `Node` from the Kubernetes API server will terminate
the old `Pods` and release the `Persistent Volumes` of type `ReadWriteOnce`, to be mounted by any new `Pods`.


If multiple `Availability Domains` are used in the Kubernetes cluster, then the replacement `Node` should be added to the same `Availability Domain`
that the deleted `Node` occupied. This allows the `Pods` to be scheduled on the replacement `Node` that can reach the `Persistent Volumes` in that
`Availability Domain`, and then the `Pod` status is changed to `Running`.


Do not forcefully delete `Pods` or `Persistent Volumes` in a failed `Node` that you plan to recover or replace. If you force delete `Pods` or `Persistent Volumes` in a failed `Node`,
it may lead to loss of data and, in the case of `Statefulsets`, it may lead to split-brain scenarios. For more information about `Statefulsets`,
see [Force Delete StatefulSet Pods](https://kubernetes.io/docs/tasks/run-application/force-delete-stateful-set-pod/) in the Kubernetes documentation.

You can force delete `Pods` and `Persistent Volumes` when a failed `Node` cannot be recovered or replaced in the same `Availability Domain` as
the original `Node`.   
