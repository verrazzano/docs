---
title: Customize High Availability
description: Achieve high availability using the `prod` profile
Weight: 6
draft: false
aliases:
  - /docs/customize/ha
---

High availability designs follow three main principles:
* Elimination of single points of failure
* Fault detection
* Reliable failover points

Verrazzano provides a means to eliminate single points of failure among critical Verrazzano components. This is accomplished by increasing replica counts, anti-affinity rules, and implementing replicated data for components that rely on MySQL and OpenSearch.

The [`ha.yaml`]({{< ghlink raw=true path="examples/ha/ha.yaml" >}}) file illustrates how the `prod` profile can be extended to configure a highly available Verrazzano installation. The increased replica counts, along with the anti-affinity rules inherited from the `prod` profile, ensure that the pods of each component are distributed across the Kubernetes cluster nodes.
MySQL and OpenSearch are configured to replicate data among replicas to avoid data loss.

The [`ha-oci-ccm.yaml`]({{< ghlink raw=true path="examples/ha/ha-oci-ccm.yaml" >}}) file configures a highly available Verrazzano installation on OCNE.

The [`ha-ext-lb.yaml`]({{< ghlink raw=true path="examples/ha/ha-ext-lb.yaml" >}}) file configures a highly available Verrazzano installation using external load balancers.


Fault detection is managed natively by using Kubernetes `Services` and Istio `VirtualServices` that detect failed pods and route traffic to the remaining replicas.

MySQL and OpenSearch provide reliable failover points for the replicated data.

The result of these measures would be no loss of service if a cluster node became unavailable. For more information regarding node failure and recovery, read the [Node Failure Guide]({{< relref "docs/guides/ha/node-failure.md" >}}).

When using the [`ha.yaml`]({{< ghlink raw=true path="examples/ha/ha.yaml" >}}) file, consider the following:

* It does not ensure a fault-tolerant environment. Your applications still must be designed and implemented as highly available.
* Running additional replicas of components will increase resource requirements. At least four CPUs, 100 GB disk storage, and 64 GB RAM available on the Kubernetes worker nodes is required.
* Additional customizations may be required for your environment, including other customizations described in individual sections.

For the expected behavior of the [MySQL Component]({{< relref "docs/reference/vpo-verrazzano-v1beta1.md#install.verrazzano.io/v1beta1.MySQLComponent" >}}) in a highly available environment, see [Customize Keycloak and MySQL]({{< relref "docs/security/keycloak/keycloak.md" >}}).

Follow these best practices for a highly available Verrazzano installation:
* Size your Kubernetes cluster according to your node failure tolerance and workload requirements.
* Set the default `Storage Class` to one with a `VolumeBindingMode` of `WaitForFirstConsumer`. This is important for being able to recover from an `Availability Domain` or zone failure.
* Set the replica counts to values that correspond to your node failure tolerance.


To install the example high availability configuration using the Verrazzano CLI:
{{< clipboard >}}
<div class="highlight">

   ```
   $ vz install -f {{< ghlink raw=true path="examples/ha/ha.yaml" >}}
   ```

</div>
{{< /clipboard >}}

Using the Verrazzano CLI, install the example high availability configuration on OCNE as follows:
{{< clipboard >}}
<div class="highlight">

   ```
    $ vz install -f {{< ghlink raw=true path="examples/ha/ha-oci-ccm.yaml" >}}
   ```

</div>
{{< /clipboard >}}

Using the Verrazzano CLI, install the example high availability configuration with external load balancers as follows:
{{< clipboard >}}
<div class="highlight">

   ```
   $ vz install -f {{< ghlink raw=true path="examples/ha/ha-ext-lb.yaml" >}}
   ```

</div>
{{< /clipboard >}}
### Upgrade recommendations
An OKE in-place upgrade scales the cluster to N-1 nodes, where N is the original number of nodes, so you must scale the cluster back to N.
This will start a new replacement node using the new node pool.
For more information on in-place upgrades, see [Performing an In-Place Worker Node Kubernetes Upgrade by Updating an Existing Node Pool](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengupgradingk8sworkernode.htm#Performi).
