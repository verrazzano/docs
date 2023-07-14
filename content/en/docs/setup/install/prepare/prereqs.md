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
- `dev` profile - At least two CPUs, 100 GB disk storage, and 16 GB RAM available on the Kubernetes worker nodes. Depending on the resource requirements of the applications you deploy, this may or may not be sufficient.
- `prod` profile - At least four CPUs, 100 GB disk storage, and 32 GB RAM available on the Kubernetes worker nodes.  Depending on the resource requirements of the applications you deploy, this may or may not be sufficient.

{{< alert title="NOTE" color="warning" >}}
To avoid conflicts with Verrazzano system components, we recommend installing Verrazzano into an empty cluster.
{{< /alert >}}

## Supported hardware
Verrazzano requires x86-64; other architectures are not supported.

## Supported software versions
Verrazzano supports the following software versions.

### Kubernetes
You can install Verrazzano on the following Kubernetes versions.

| Verrazzano | Kubernetes Versions    |
|------------|------------------------|
| 1.4        | 1.21, 1.22, 1.23, 1.24 |
| 1.3        | 1.21, 1.22, 1.23       |
| 1.2        | 1.19, 1.20, 1.21       |
| 1.1        | 1.19, 1.20, 1.21       |
| 1.0        | 1.18, 1.19, 1.20       |

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

### Verrazzano installed software

For a detailed list of Verrazzano installed software, see [here]({{< relref "/docs/setup/install/verify/softwares.md" >}}).
