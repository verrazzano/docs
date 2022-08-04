---
title: Configure High Availability
description: Achieve high availability using the `prod` profile
linkTitle: High Availability
Weight: 11
draft: false
---

The [ha.yaml]({{< ghlink raw=true path="examples/ha/ha.yaml" >}}) file shows you how the `prod` profile can be extended to configure a highly available Verrazzano installation. The increased replica counts, along with the affinity rules inherited from the `prod` profile, ensure that the pods of each component are distributed across the Kubernetes cluster nodes.  There would be no loss of service if a cluster node became unavailable.

When using [ha.yaml]({{< ghlink raw=true path="examples/ha/ha.yaml" >}}), consider the following:

* It does not ensure a fault-tolerant environment.
* Running additional replicas of components will increase resource requirements. At least four CPUs, 100GB disk storage, and 64GB RAM available on the Kubernetes worker nodes is required.
* Additional customizations may be required for your environment.

To install the example high availability configuration using the Verrazzano CLI:
   ```
   $ vz install -f {{< ghlink raw=true path="examples/ha/ha.yaml" >}}
   ```
