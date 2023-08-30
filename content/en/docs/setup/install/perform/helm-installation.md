---
title: "Install With Helm"
description: "Install Verrazzano using Helm"
weight: 3
draft: false
---

The following instructions show you how to install the Verrazzano Platform Operator (VPO) in a
single Kubernetes cluster using Helm.

## Prerequisites

- Find the Verrazzano prerequisite requirements [here]({{< relref "/docs/setup/install/prepare/prereqs.md" >}}).
- Review the list of the [software versions supported]({{< relref "/docs/setup/install/prepare/prereqs.md#supported-software-versions" >}}) and [installed]({{< relref "/docs/setup/install/prepare/prereqs.md#installed-components" >}}) by Verrazzano.
- [Helm](https://helm.sh)

{{< alert title="NOTE" color="primary" >}}
To avoid conflicts with Verrazzano system components, we recommend installing Verrazzano into an empty cluster.
{{< /alert >}}

{{< alert title="NOTE" color="warning" >}}
Helm chart installation is supported only for Verrazzano v1.6.0 and later.
{{< /alert >}}

## Prepare for the installation

Before installing the Verrazzano platform operator, see the instructions for preparing [Kubernetes platforms]({{< relref "/docs/setup/install/prepare/platforms/" >}}).
Make sure that you have a valid kubeconfig file pointing to the Kubernetes cluster that you want to use for installing your Verrazzano platform operator.

**NOTE**: Verrazzano can create network policies that can be used to limit the ports and protocols that pods use for network communication. Network policies provide additional security but they are enforced only if you install a Kubernetes Container Network Interface (CNI) plug-in that enforces them, such as Calico. For instructions on how to install a CNI plug-in, see the documentation for your Kubernetes cluster.

## Perform the installation

Verrazzano provides a platform [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.

The following steps show you how to install the VPO using a VPO Helm chart. VPO Helm charts are located in Verrazzano versioned repositories [here](https://github.com/orgs/verrazzano/packages/container/charts%2Fverrazzano-platform-operator/versions?filters%5Bversion_type%5D=tagged).

#### Install the VPO using a Helm chart from the repository

1. Install your desired version of the Verrazzano platform operator. See the following example command that installs the v1.6.5 VPO. 
   {{< clipboard >}}
<div class="highlight">

    $ helm install your-release-name oci://ghcr.io/verrazzano/charts/verrazzano-platform-operator --version 1.6.5

</div>
{{< /clipboard >}}

   This command installs only the VPO to the cluster; it does not install a Verrazzano Custom Resource.

2. Follow the steps in this [section]({{< relref "docs/setup/install/perform/kubectl-installation#perform-the-installation" >}}) to apply the Verrazzano Custom Resource and complete the installation of Verrazzano.