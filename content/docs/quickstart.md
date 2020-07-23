---
title: "Quick Start"
weight: 1
---

# Quick Start

Welcome to Oracle Verrazzano Enterprise Container Platform. Verrazzano is a curated
collection of open source components that form a complete platform
for deploying and managing your container applications across multiple Kubernetes clusters.

## About this Quick Start

This Quick Start guide describes how to quickly and easily set up Verrazzano in
a single cluster environment with sensible defaults.
This is primarily intended for setting up an environment for development and testing purposes.

The Quick Start may be run either on [Oracle Cloud Infrastructure Container Engine for
Kubernetes](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengoverview.htm) (OKE)
or on [kind](https://kind.sigs.k8s.io/docs/user/quick-start/) (Kubernetes in Docker).

{{< hint info >}}
To install Verrazzano in a production environment, see the [Installation]() section instead.
{{< /hint >}}

### Prerequisites

To follow the Quick Start guide, you must have:
* An Oracle Cloud account with permission to create OKE clusters.
* At least 2 VMs available in your tenancy, with a shape equivalent to or better than VM.Standard2.4.
* An Oracle ID for pulling images from the [Oracle Container Registry](https://container-registry.oracle.com).

### Create a Kubernetes cluster

{{< tabs "tabs-create-cluster" >}}
{{< tab "OKE" >}}
To create an OKE cluster:

1. Log in to the [OCI Console](https://console.us-phoenix-1.oraclecloud.com/).
1. Navigate to Developer Services and select the "Container Clusters (OKE)" page.
1. Click **Create Cluster**.
1. Use the "Quick Create" option to create a cluster with the following required
   network resources, then click **Launch Workflow**.
    * Use Kubernetes version 1.16.8 or later.
	* Choose a shape with at least 4 cores, for example `VM.Standard2.4`.
	* Create at least three nodes.
	* If you want to use Kubernetes NodePorts to access your cluster, so that
	  you do not need an OCI Load Balancer, make sure you select Public
	  node visibility.
1. Click **Create Cluster**.
1. To access your cluster, click **Launch Cloud Shell**.
1. Copy the `kubeconfig` file to Cloud Shell.

{{< /tab >}}
{{< tab "Kind" >}}
To create a kind cluster:

1. Download the latest stable release of kind from the [kind releases page](https://github.com/kubernetes-sigs/kind/releases).
1. Rename this file `kind` and place it in your `PATH`.
1. Create a cluster using the provided sample configuration:

```bash
kind create cluster --config quickstart/kind-config.yaml
```

Reminder: The `quickstart` directory is the one you created when you cloned
the Verrazzano repository.

Kind will automatically update your `$HOME/.kube/config` file and set the correct
context and cluster for you.
{{< /tab >}}
{{< /tabs >}}

### Obtain the Verrazzano repository

Verrazzano Enterprise Container Platform software is available in open source on GitHub
at [https://github.com/verrazzano/verrazzano](https://github.com/verrazzano/verrazzano).

Clone the Verrazzano repository:

```bash
$ git clone https://github.com/verrazzano/verrazzano
$ cd verrazzano
```

{{< hint info >}}
This document will refer to this directory you just created as the `quickstart`
directory.
{{< /hint >}}

### Run the following commands:


{{< tabs "tabs-git-clone" >}}
{{< tab "OKE" >}}

```bash
$ export CLUSTER_TYPE=OKE
```
{{< /tab >}}
{{< tab "Kind" >}}

```bash
$ export CLUSTER_TYPE=KIND
```
{{< /tab >}}
{{< /tabs >}}

```bash
$ export VERRAZZANO_KUBECONFIG=~/.kube/config
$ export KUBECONFIG=~/.kube/config
$ kubectl create secret docker-registry ocr --docker-username=<username> --docker-password=<password> --docker-server=container-registry.oracle.com
```


### Install Verrazzano

Install Verrazzano in your cluster using the provided scripts:

```bash
./install/1-install-istio.sh
./install/2-install-system-components-magicdns.sh
./install/3-install-verrazzano.sh
./install/4-install-keycloak.sh
```

### Access the environment

Verify the installation with this `kubectl` command:

```bash
kubectl get pods --all-namespaces
```

### Install the Hello World Helidon demonstration application (optional)

Follow the steps at [Hello World Helidon](https://github.com/verrazzano/verrazzano/blob/master/examples/hello-helidon/README.md).
