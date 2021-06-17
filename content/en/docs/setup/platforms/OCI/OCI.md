---
title: Oracle Cloud Infrastructure (OCI)
description: Instructions for setting up an Oracle Cloud Infrastructure Container Engine for Kubernetes (OKE) cluster for Verrazzano
linkTitle: OCI
Weight: 5
draft: false
---

### Prepare for the OCI install

* Create the [OKE](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengoverview.htm) cluster using the OCI Console or some other means.  

* For `SHAPE`, an OKE cluster with 3 nodes of `VM.Standard2.4` [OCI compute instance shape](https://www.oracle.com/cloud/compute/virtual-machines.html) has proven sufficient to install Verrazzano and deploy the Bob's Books example application.

* Set the following `ENV` variable:

```
   $ export KUBECONFIG=<path to valid Kubernetes config>
```

* Optional step, needed only if your organization requires the use of a private registry to host one or more of the Docker images installed by
  Verrazzano and those images have been loaded into the private registry. Create the optional `imagePullSecret` named `verrazzano-container-registry`.

```
   $ kubectl create secret docker-registry verrazzano-container-registry \
    --docker-username=<username> \
    --docker-password=<password> \
    --docker-server=<docker server of private registry>
```

**NOTE**: Verrazzano can create network policies that can be used to limit the ports and protocols that pods use for network communication. Network policies provide additional security but they are enforced only if you install a Kubernetes Container Network Interface (CNI) plug-in that enforces them, such as Calico. For an example on OKE, see [Installing Calico and Setting Up Network Policies](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengsettingupcalico.htm).

### Next steps

To continue, see the [Installation Guide]({{< relref "/docs/install/installation.md#install-the-verrazzano-platform-operator" >}}).
