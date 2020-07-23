---
title: "Install Istio"
weight: 2
---

# Install Istio

Verrazzano requires Istio 1.4.6 installed in the multi-cluster single control
plane model with mutual TLS enabled.

## Prepare the Istio configuration file



## Install Istio

To install Istio:

* Create a directory to hold the installation files, and change to this directory,
  for example:

    ```bash
    mkdir $HOME/install
    cd $HOME/install
    ```

* Download Istio as follows:

    ```bash
    curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.4.6 sh -
    ```

* Ensure you have `kubectl` configured to point to the correct cluster, for example
  by setting the `KUBECONFIG` environment variable, or setting the correct cluster
  and context using the `kubectl config` commands.  Refer to the `kubectl` documentation
  for more details.

* Install Istio into the first cluster - the one that is designated as the "management
  cluster" if you have more than one cluster.

    ```bash
    istio-1.4.6/bin/istioctl manifest apply \
       --set values.gateways.istio-ingressgateway.type=NodePort
    ```

* TODO - add details about how to install in the rest of the clusters and how to create
  the mesh    
