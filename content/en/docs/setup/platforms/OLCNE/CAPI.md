---
title: Cluster API Provider for Oracle Cloud Native Environment
linkTitle: CAPI Provider for OCNE
weight: 5
draft: false
---

The Cluster API (CAPI) project seeks to develop and standardize Kubernetes-style APIs specific to cluster management. External organizations then can use these standard APIs to develop cluster management solutions built to their preferred requirements.

Learn more about CAPI at [Kubernetes Cluster API Documentation](https://cluster-api.sigs.k8s.io/introduction.html).

CAPI spreads the various cluster management tasks across three types of providers: 

* **Infrastructure** providers standardize the host environment by provisioning any infrastructure or computational resources required by the cluster or machine. 

* **Bootstrap** providers streamline the node creation process by converting servers into Kubernetes nodes. 

* **Control plane** providers work with the Kubernetes API to regulate your clusters, ensuring that they always strive toward a desired state. 

The CAPI provider for Oracle Cloud Native Environment (CAPOCNE) includes both a bootstrap and a control plane provider. When you enable Verrazzano with CAPOCNE on an Oracle Cloud Native Environment, you can use it to rapidly design and deploy clusters and then continue managing your clusters throughout their life cycle.

During the setup process, the bootstrap provider converts a cluster into a management cluster - a Kubernetes cluster that controls any other, subordinate or 'workload' clusters. It generates certificates, starts and manages the creation of additional nodes, and handles the addition of control plane and worker nodes to the cluster.

Next, a CAPI *infrastructure* provider will provision the first instance on the cloud provider and generate a provider ID, a unique identifier that any future nodes and clusters will use to associate with the instance. It will also create a kubeconfig file. The first control plane node is ready after these are created.

After the management cluster is up and running, you can use CAPOCNE to create additional workload clusters.

CAPOCNE currently works only with the [CAPOCI infrastructure provider](https://github.com/oracle/cluster-api-provider-oci) offered by Oracle Cloud Infrastructure (OCI).

{{% alert title="NOTE" color="primary" %}}
The terminology around clusters differs between CAPI and Verrazzano though the underlying concepts are the same. What CAPI calls Management and Workload clusters are equivalent to Admin and Managed clusters, respectively, in Verrazzano.
{{% /alert %}}