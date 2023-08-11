---
title: Prepare an Oracle Cloud Infrastructure Container Engine for Kubernetes (OKE) Cluster
description: Set up an Oracle Cloud Infrastructure Container Engine for Kubernetes (OKE) cluster for Verrazzano
Weight: 2
draft: false
aliases:
  - /docs/setup/platforms/oci/oci
---

## Prepare for the Oracle Cloud Infrastructure installation

* Create the [OKE](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengoverview.htm) cluster using the Oracle Cloud Infrastructure Console or by some other means.  

* Follow the instructions provided by OKE to download the Kubernetes configuration file for your cluster, and set the following `ENV` variable:
{{< clipboard >}}
<div class="highlight">

    $ export KUBECONFIG=<path to valid Kubernetes config>

</div>
{{< /clipboard >}}

* Optional, if your organization requires the use of a private registry to the Docker images installed by Verrazzano, see [Use a Private Registry]({{< relref "/docs/setup/private-registry/private-registry.md" >}}).

**NOTE**: Verrazzano can create network policies that can be used to limit the ports and protocols that pods use for network communication. Network policies provide additional security but they are enforced only if you install a Kubernetes Container Network Interface (CNI) plug-in that enforces them, such as Calico. For an example on OKE, see [Installing Calico and Setting Up Network Policies](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengsettingupcalico.htm).

{{< alert title="NOTE" color="primary" >}} OCI VCN-Native Pod Networking is now supported with Verrazzano for Kubernetes v1.26 and up. 
The pod network must be in a private subnet to enable egress.
Either place the worker nodes in a private subnet, or place the pod network in a private subnet separate from the worker nodes.
For Kubernetes v1.25 and below, use the flannel overlay network.
{{< /alert >}}

## Next steps

To continue, see the [Installation Guide]({{< relref "/docs/setup/install/" >}}).
