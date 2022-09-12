---
title: Configure High Availability
description: Achieve high availability using the `prod` profile
linkTitle: High Availability
Weight: 11
draft: false
---

High availability designs follow three main principles:
* Elimination of single points of failure
* Fault detection
* Reliable failover points

Verrazzano provides a means to eliminate single points of failure among critical Verrazzano components. This is accomplished by increasing replica counts, anti-affinity rules, and implementing replicated data for components that rely on MySQL and OpenSearch.

The [`ha.yaml`]({{< ghlink raw=true path="examples/ha/ha.yaml" >}}) file illustrates how the `prod` profile can be extended to configure a highly available Verrazzano installation. The increased replica counts, along with the anti-affinity rules inherited from the `prod` profile, ensure that the pods of each component are distributed across the Kubernetes cluster nodes.
MySQL and OpenSearch are configured to replicate data among replicas to avoid data loss.

Fault detection is managed natively by using Kubernetes `Services` and Istio `VirtualServices` that detect failed pods and route traffic to the remaining replicas.

MySQL and OpenSearch provide reliable failover points for the replicated data.

The result of these measures would be no loss of service if a cluster node became unavailable. For more information regarding node failure and recovery, read the [Node Failure Guide]({{< relref "docs/guides/ha/node-failure.md" >}}).

When using the [`ha.yaml`]({{< ghlink raw=true path="examples/ha/ha.yaml" >}}) file, consider the following:

* It does not ensure a fault-tolerant environment. Your applications still must be designed and implemented as highly available.
* Running additional replicas of components will increase resource requirements. At least four CPUs, 100GB disk storage, and 64GB RAM available on the Kubernetes worker nodes is required.
* Additional customizations may be required for your environment, including other customizations described in this documentation.

Follow these best practices for a highly available Verrazzano installation:
* Size your Kubernetes cluster according to your node failure tolerance and workload requirements.
* Set the default `Storage Class` to one with a `VolumeBindingMode` of `WaitForFirstConsumer`. This is important for being able to recover from an `Availability Domain` or zone failure.
* Set the replica counts to values that correspond to your node failure tolerance.


To install the example high availability configuration using the Verrazzano CLI:
   ```
   $ vz install -f {{< ghlink raw=true path="examples/ha/ha.yaml" >}}
   ```
