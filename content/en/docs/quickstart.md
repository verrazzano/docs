---
title: "Quick Start"
description: "Instructions for getting started with Verrazzano"
weight: 2
---

Verrazzano is an end-to-end enterprise container platform for deploying cloud-native and traditional applications in multi-cloud and hybrid environments. It is made up of a curated set of open source components – many that you may already use and trust, and some that were written specifically to pull together all of the pieces that make Verrazzano a cohesive and easy to use platform.

Verrazzano includes the following capabilities:

* Hybrid and multi-cluster workload management
* Special handling for WebLogic, Coherence, and Helidon applications
* Multi-cluster infrastructure management
* Integrated and pre-wired application monitoring
* Integrated security
* DevOps and GitOps enablement

This [repository](https://github.com/verrazzano/verrazzano) contains installation scripts and example applications for use with Verrazzano.

{{< alert title="NOTE" color="warning" >}}
This is a developer preview release of Verrazzano. It is intended for installation in a single cluster on
[Oracle Cloud Infrastructure Container Engine for Kubernetes (OKE)](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengoverview.htm)
or [Oracle Linux Cloud Native Environment (OLCNE)](https://docs.oracle.com/en/operating-systems/olcne/).
You should install Verrazzano only in a cluster that can be safely deleted when your evaluation is complete.
{{< /alert >}}

## Install Verrazzano

To install Verrazzano, follow these steps:

1. Create an [Oracle Cloud Infrastructure Container Engine for Kubernetes (OKE)](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengoverview.htm) cluster.
1. Launch [OCI Cloud Shell](https://docs.cloud.oracle.com/en-us/iaas/Content/API/Concepts/cloudshellgettingstarted.htm).
1. Set up a [kubeconfig](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) file in the OCI Cloud Shell for the OKE cluster. See these detailed [instructions](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengdownloadkubeconfigfile.htm).


1. Clone this [repo](https://github.com/verrazzano/verrazzano) into the home directory of the OCI Cloud Shell.

    `git clone https://github.com/verrazzano/verrazzano`

    `cd verrazzano`

1. Run the following commands in the OCI Cloud Shell:

    `export CLUSTER_TYPE=OKE`

    `export VERRAZZANO_KUBECONFIG=~/.kube/config`

    `export KUBECONFIG=~/.kube/config`

    `./install/1-install-istio.sh`

    `./install/2a-install-system-components-magicdns.sh`

    `./install/3-install-verrazzano.sh`

    `./install/4-install-keycloak.sh`

## Next steps

1. [Verify](https://github.com/verrazzano/verrazzano/blob/master/install/README.md#3-verify-the-install) the installation.

1. [Deploy an example application](../guides/application-deployment-guide) on Verrazzano.
