---
title: "Quick Start"
description: "Instructions for getting started with Verrazzano"
weight: 2
---

Verrazzano is an end-to-end Enterprise Container Platform for deploying cloud-native and traditional applications in multi-cloud and hybrid environments. It is made up of a curated set of open source components – many that you may already use and trust, and some that were written specifically to pull together all of the pieces that make Verrazzano a cohesive and easy to use platform.

Verrazzano Enterprise Container Platform includes the following capabilities:

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
You should only install Verrazzano in a cluster that can be safely deleted when your evaluation is complete.
{{< /alert >}}

## Install Verrazzano

To install Verrazzano, follow these steps:

1. Create an [Oracle Cloud Infrastructure Container Engine for Kubernetes (OKE)](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengoverview.htm) cluster.
1. Launch [OCI Cloud Shell](https://docs.cloud.oracle.com/en-us/iaas/Content/API/Concepts/cloudshellgettingstarted.htm).
1. Set up a [kubeconfig](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) file in the OCI Cloud Shell for the OKE cluster. See these detailed [instructions](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengdownloadkubeconfigfile.htm).
1. Clone this [repo](https://github.com/verrazzano/verrazzano) into the home directory of the OCI Cloud Shell.
   - `git clone https://github.com/verrazzano/verrazzano`
   - `cd verrazzano`
1. Execute the following commands in the OCI Cloud Shell:
   - `export CLUSTER_TYPE=OKE`
   - `export VERRAZZANO_KUBECONFIG=~/.kube/config`
   - `export KUBECONFIG=~/.kube/config`
   - `./install/1-install-istio.sh`
   - `./install/2a-install-system-components-magicdns.sh`
   - `./install/3-install-verrazzano.sh`
   - `./install/4-install-keycloak.sh`
1. (Optional) Install some example applications - see [Deploy the example applications](#deploy-the-example-applications).

### Deploy the example applications (optional)

See the instructions at:

- [Hello World Helidon ](https://github.com/verrazzano/verrazzano/blob/master/examples/hello-helidon/README.md)
- [Bob's Books](https://github.com/verrazzano/verrazzano/tree/master/examples/bobs-books/README.md)
- [Helidon Sock Shop](https://github.com/verrazzano/verrazzano/blob/master/examples/sock-shop/README.md)
- [ToDo List Lift-and-Shift Application](https://github.com/verrazzano/examples/blob/master/todo-list/README.md)
