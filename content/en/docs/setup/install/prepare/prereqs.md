---
title: "Prerequisites"
description: "Review the prerequisite requirements and the software versions supported by Verrazzano"
weight: 1
draft: false
aliases:
  - /docs/setup/prereqs
---


Verrazzano requires the following:
- A Kubernetes cluster and a compatible `kubectl`.
- [Two load balancers]({{< relref "/docs/networking#high-level-network-diagram" >}}). Note that in a Verrazzano multicluster environment, two load balancers are required for each cluster.
- `dev` profile - Each node in the cluster should contain at least two CPUs, 16 GB RAM, and 100 GB of disk storage. The entire cluster requires at least six CPUs, 48 GB RAM, and 100 GB of disk storage. In addition, about 52 GB of storage is required for the persistent volumes.
- `prod` profile - Each node in the cluster should contain at least four CPUs, 32 GB RAM, and 100 GB of disk storage. The entire cluster requires at least eight CPUs, 64 GB RAM, and 150 GB of disk storage. In addition, about 450 GB of storage is required for the persistent volumes.

   The persistent volumes are provisioned using the default [StorageClass](https://kubernetes.io/docs/tasks/administer-cluster/change-default-storage-class/) in the cluster. In case of a  local disk based PV [provisioner](https://kubernetes.io/docs/concepts/storage/storage-classes/#provisioner), each node in the cluster should have a minimum of 80 GB of disk storage for both of the profiles.


{{< alert title="NOTE" color="primary" >}}
To avoid conflicts with Verrazzano system components, we recommend installing Verrazzano into an empty cluster. Also, depending on the resource requirements of the applications you deploy, the configurations previously suggested may or may not be sufficient.
{{< /alert >}}

## Supported hardware
Verrazzano requires x86-64; other architectures are not supported.

## Supported software versions
Verrazzano supports the following software versions.

### Kubernetes
You can install Verrazzano on the following Kubernetes versions.

| Verrazzano | Release Date | Latest Patch Release | Latest Patch Release Date | End of Error Correction* | Kubernetes Versions    |
|------------|--------------|----------------------|---------------------------|--------------------------|------------------------|
| 1.5        | 2023-02-15   | 1.5.3                | 2023-05-09                | 2024-02-28**             | 1.21, 1.22, 1.23, 1.24 |
| 1.4        | 2022-09-30   | 1.4.4                | 2023-03-15                | 2023-10-31               | 1.21, 1.22, 1.23, 1.24 |
| 1.3        | 2022-05-24   | 1.3.8                | 2022-11-17                | 2023-05-31               | 1.21, 1.22, 1.23       |
| 1.2        | 2022-03-14   | 1.2.2                | 2022-05-10                | 2022-11-30               | 1.19, 1.20, 1.21       |
| 1.1        | 2021-12-16   | 1.1.2                | 2022-03-09                | 2022-09-30               | 1.19, 1.20, 1.21       |
| 1.0        | 2021-08-02   | 1.0.4                | 2021-12-20                | 2022-06-30               | 1.18, 1.19, 1.20       |

*_End of error correction for Verrazzano releases._<br>
**_Projected date. Actual date will be determined when the next minor or major release is available._

<br>

For more information, see [Kubernetes Release Documentation](https://kubernetes.io/releases/).
<br>For platform specific details, see [Verrazzano platform setup]({{< relref "/docs/setup/install/prepare/platforms/_index.md" >}}).

### WebLogic Server
The supported versions of WebLogic Server are dependent on the [WebLogic Kubernetes Operator](https://oracle.github.io/weblogic-kubernetes-operator/) version.
See the WebLogic Server versions supported [here](https://oracle.github.io/weblogic-kubernetes-operator/introduction/prerequisites/introduction/).


### Coherence
The supported versions of Coherence are dependent on the [Coherence Operator](https://oracle.github.io/coherence-operator/docs/latest/#/about/01_overview) version.
See the Coherence versions supported [here](https://oracle.github.io/coherence-operator/docs/latest/#/docs/installation/01_installation).

### Helidon
Verrazzano supports all versions of Helidon.  For more information, see [Helidon](https://helidon.io) and
 [Helidon Commercial Offerings](https://support.oracle.com/knowledge/Middleware/2645279_1.html).
