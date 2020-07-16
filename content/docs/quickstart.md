---
title: "Quick Start"
weight: 1
---

# Quick Start

Welcome to Oracle Verrazzano Enterprise Container Platform. Verrazzano is a curated
collection of open source and Oracle-authored components that form a complete platform
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

### Obtain the Verrazzano Quick Start samples

Verrazzano Enterprise Container Platform software is available in open source on GitHub
at [https://github.com/verrazzano](https://github.com/verrazzano).

To follow the Quick Start guide, you must:
* Meet the following prerequisites:
  - An Oracle Cloud account with permission to create OKE clusters.
  - At least 2 VMs available in your tenancy, with a shape equivalent to or better than VM.Standard2.4.
  - An Oracle ID for pulling images from the Oracle Container Registry.

* Download the appropriate sample files:

{{< tabs "tabs-git-clone" >}}
{{< tab "OKE" >}}
Clone the samples repository:

```bash
git clone https://github.com/verrazzano/quickstart-oke
```
{{< /tab >}}
{{< tab "Kind" >}}
Clone the samples repository:

```bash
git clone https://github.com/verrazzano/quickstart-kind
```
{{< /tab >}}
{{< /tabs >}}

{{< hint info >}}
This document will refer to this directory you just created as the `quickstart`
directory.
{{< /hint >}}

### Create a Kubernetes cluster

{{< tabs "tabs-create-cluster" >}}
{{< tab "OKE" >}}
To create an OKE cluster:

1. Log in to the [OCI Console](https://console.us-phoenix-1.oraclecloud.com/).
1. Navigate to Developer Services and select the "Container Clusters (OKE)" page.
1. Click **Create Cluster**.
1. Use the "Quick Create" option to create a cluster with the following required
   network resources, then click **Launch Workflow**.
    * Use Kubernetes version 1.15 or later.
	* Choose a shape with at least 4 cores, for example `VM.Standard2.4`.
	* Create at least three nodes.
	* If you want to use Kubernetes NodePorts to access your cluster, so that
	  you do not need an OCI Load Balancer, make sure you select Public
	  node visibility.
1. Click **Create Cluster**.
1. Follow the provided instructions to obtain the `kubeconfig` file and save
   that on your machine.
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
the sample repostiory in the previous step.

Kind will automatically update your `$HOME/.kube/config` file and set the correct
context and cluster for you.
{{< /tab >}}
{{< /tabs >}}

### Install Istio

Install Istio in your cluster using the provided script:

```bash
quickstart/install-istio.sh
```

### Install Rancher

Install Rancher in your cluster using the provided script:

```bash
quickstart/install-rancher.sh
```

### Install Verrazzano

Install Verrazzano in your cluster using the provided script:

```bash
quickstart/install-verrazzano.sh
```

### Access the environment

Verify the installation with this `kubectl` command:

```bash
kubectl get pods --all-namespaces
```

### Install the Bob's Books demonstration application (optional)

To install the sample application:

1. clone repo
2. create secrets
3. apply model
4. apply binding
