---
title: Cluster API
linkTitle: Cluster API
description: Use Verrazzano to create and manage new clusters
weight: 1
draft: false
---

The Cluster API (CAPI) project was developed as a sub-project of Kubernetes and strives to standardize a set of Kubernetes-style APIs for cluster management. External organizations can then build upon these standard APIs to develop custom cluster management solutions.

Learn more about CAPI at [Kubernetes Cluster API Documentation](https://cluster-api.sigs.k8s.io/introduction.html).

Verrazzano incorporates CAPI functionality through the clusterAPI component, which provides the ability to quickly design and deploy clusters and then continue managing your clusters throughout their life cycle, all from within Verrazzano.

{{% alert title="NOTE" color="primary" %}}
The terminology around clusters differs between CAPI and Verrazzano though the underlying concepts are the same. What CAPI calls Management and Workload clusters are equivalent to Admin and Managed clusters, respectively, in Verrazzano.
{{% /alert %}}

CAPI splits cluster management responsibilities across three main components, which it calls providers: 

* **Infrastructure** providers standardize the host environment by provisioning any infrastructure or computational resources required by the cluster or machine. 

* **Bootstrap** providers streamline the node creation process by converting servers into Kubernetes nodes. 

* **Control plane** providers work with the Kubernetes API to regulate your clusters, ensuring that they always strive toward a desired state. 

Currently, Verrazzano supports the CAPI provider for Oracle Cloud Native Environment (CAPOCNE) which bundles a bootstrap and a control plane provider together and works with the [CAPOCI infrastructure provider](https://github.com/oracle/cluster-api-provider-oci) offered by Oracle Cloud Infrastructure (OCI).

During the setup process, the bootstrap provider converts a cluster into an admin cluster - a Kubernetes cluster that controls any other, subordinate or 'managed' clusters. It generates certificates, starts and manages the creation of additional nodes, and handles the addition of control plane and worker nodes to the cluster.

Next, a CAPI infrastructure provider will provision the first instance on the cloud provider and generate a provider ID, a unique identifier that any future nodes and clusters will use to associate with the instance. It will also create a kubeconfig file. The first control plane node is ready after these are created.

After the admin cluster is up and running, you can use the clusterAPI component to create additional managed clusters.
