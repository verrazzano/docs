---
title: OCI Container Engine for Kubernetes (OKE)
description: Instructions for setting up an Oracle Cloud Infrastructure Container Engine for Kubernetes (OKE) cluster for Verrazzano
linkTitle: OKE
Weight: 5
draft: false
---

## Prepare for the OCI install

* Create the [OKE](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengoverview.htm) cluster using the OCI Console or by some other means.  

* For `SHAPE`, an OKE cluster with 3 nodes of `VM.Standard2.4` [OCI compute instance shape](https://www.oracle.com/cloud/compute/virtual-machines.html) has proven sufficient to install Verrazzano and deploy the Bob's Books example application.

* Follow the instructions provided by OKE to download the Kubernetes configuration file for your cluster, and set the following `ENV` variable:

```
   $ export KUBECONFIG=<path to valid Kubernetes config>
```

* Optional, if your organization requires the use of a private registry to the Docker images installed by Verrazzano, see [Using a Private Registry]({{< relref "/docs/setup/private-registry/private-registry.md" >}}).

**NOTE**: Verrazzano can create network policies that can be used to limit the ports and protocols that pods use for network communication. Network policies provide additional security but they are enforced only if you install a Kubernetes Container Network Interface (CNI) plug-in that enforces them, such as Calico. For an example on OKE, see [Installing Calico and Setting Up Network Policies](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengsettingupcalico.htm).

## Next steps

To continue, see the [Installation Guide]({{< relref "/docs/setup/install/installation.md#install-the-verrazzano-platform-operator" >}}).
