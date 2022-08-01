---
title: Configure High Availability
description: Using the `prod` profile to achieve a high availability installation
linkTitle: Configure High Availability
Weight: 5
draft: false
---

The file [ha.yaml]({{< ghlink raw=true path="examples/ha/ha.yaml" >}}) is an example of how the `prod` profile can be extended to configure a Verrazzano installation to be highly available. The increased replica counts, along with the affinity rules inherited from the `prod` profile, ensure the pods of each component are distributed across the Kubernetes cluster nodes.  There would be no loss of service if a cluster node became unavailable.

When using [ha.yaml]({{< ghlink raw=true path="examples/ha/ha.yaml" >}}), consider the following:

* It does not ensure a fault-tolerant environment
* Additional customizations may be required for your environment
* Running additional replicas of components will increase resource requirements

How to install the example high availability configuration using the Verrazzano CLI:
   ```
   $ vz install -f {{< ghlink raw=true path="examples/ha/ha.yaml" >}}
   ```
