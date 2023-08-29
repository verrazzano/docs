---
title: "Install With Helm"
description: "Install Verrazzano using Helm"
weight: 3
draft: false
aliases:
- /docs/setup/install/installation
- /docs/setup/install/cli-installation
---

The following instructions show you how to install the Verrazzano Platform Operator (VPO) in a
single Kubernetes cluster using Helm 

## Prerequisites

- Find the Verrazzano prerequisite requirements [here]({{< relref "/docs/setup/install/prepare/prereqs.md" >}}).
- Review the list of the [software versions supported]({{< relref "/docs/setup/install/prepare/prereqs.md#supported-software-versions" >}}) and [installed]({{< relref "/docs/setup/install/prepare/prereqs.md#installed-components" >}}) by Verrazzano.
- [Helm](https://helm.sh)

{{< alert title="NOTE" color="primary" >}}
To avoid conflicts with Verrazzano system components, we recommend installing Verrazzano into an empty cluster.
{{< /alert >}}

{{< alert title="NOTE" color="primary" >}}
Helm Chart Installation is only support for 1.6.0 releases and onward.
{{< /alert >}}

## Prepare for the installation

Before installing a Verrazzano platform operator, see instructions on preparing [Kubernetes platforms]({{< relref "/docs/setup/install/prepare/platforms/" >}}).
Make sure that you have a valid kubeconfig file pointing to the Kubernetes cluster that you want to use for installing your Verrazzano Platform Operator.

**NOTE**: Verrazzano can create network policies that can be used to limit the ports and protocols that pods use for network communication. Network policies provide additional security but they are enforced only if you install a Kubernetes Container Network Interface (CNI) plug-in that enforces them, such as Calico. For instructions on how to install a CNI plug-in, see the documentation for your Kubernetes cluster.

## Perform the installation

Verrazzano provides a platform [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.

This document shows how to install a VPO using a Verrazzano VPO Helm chart, which can be found in one of our [repositories](https://github.com/orgs/verrazzano/packages/container/charts%2Fverrazzano-platform-operator/versions?filters%5Bversion_type%5D=tagged)

#### Install Verrazzano Platform Operator

To install a VPO Using a Helm Chart From Our Repository.

1. Install your desired version of the Verrazzano VPO 
   {{< clipboard >}}
<div class="highlight">

    $ helm install your-release-name oci://ghcr.io/verrazzano/charts/verrazzano-platform-operator --version 1.6.5

</div>
{{< /clipboard >}}

This example command installs only the 1.6.5 VPO to the cluster, it does not install a Verrazzano Custom Resource. To formally trigger an install of Verrazzano in your cluster, the custom resource [must be applied to your cluster]({{< relref "docs/setup/install/perform/kubectl-installation.md#perform-the-installation" >}}).