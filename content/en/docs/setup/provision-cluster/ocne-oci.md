---
title: Create Oracle Cloud Native Environment clusters running on OCI
description: "Add OCNE managed clusters running on OCI to your multicluster environment"
weight: 1
draft: false
---

### Before you begin

You'll need:

* An Oracle Cloud Infrastructure (OCI) account with a compartment configured
* An SSH key pair to use for cluster authentication

### Create a new OCNE cluster on OCI 

To provision new Oracle Cloud Native Environment (OCNE) managed clusters on OCI, complete the following steps:

1. Log into the Rancher console. Find the Rancher console URL for your cluster at [Get console URLs]({{< relref "/docs/setup/access/console-urls.md" >}}).
1. Open the navigation menu and select **Cluster Management**.
1. From the left menu, select **Cloud Credentials**, and then click **Create**. Cloud credentials store the credentials for your cloud infrastructure provider.
1. Choose **Oracle**.
1. Provide a name for the cloud credential and then fill in the fields. You can find the required information in your [OCI configuration file](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#Required_Keys_and_OCIDs). Click **Create**.
1. From the left menu, select **Clusters**, and then click **Create**.
1. Select **Oracle OCNE on OCI** and provide a name for the cluster.
1. Expand **Member Roles** to add any users that you want grant access to this cluster and their permissions.
1. Expand **Labels and Annotations** to configure Kubernetes [labels](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/) and [annotations](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) for the cluster.
1. Select the cloud credentials that you created. Ensure that the appropriate Region and Compartment are selected from their dropdown lists. 
1. Click **Authenticate and Configure Cluster**.
1. Set up your network. Choose **Quick Create** to build a new virtual cloud network (VCN) using default settings or **Existing Infrastructure** to use an already configured VCN. If you choose to use an existing VCN, make sure that it is configured to accept the [ports and protocols required by Kubernetes](https://kubernetes.io/docs/reference/networking/ports-and-protocols/).
1. Click **Configure Control plane and worker nodes**.
1. Choose a Node Image from the dropdown list.
1. Expand **OCNE Image Configuration** if you want to modify the default settings. You can add an optional custom image OCID to override the default settings of the node image and you can block the installation of OCNE dependencies on each node.
1. Copy or upload an SSH public key to manage authentication of the cluster.
1. Configure the Control Plane. Select the **OCNE Version** first as it determines which Kubernetes versions are available, then choose a **Kubernetes Version** and a **Control Plane Shape**. You can leave the rest of the options at their default setting or modify them as needed.
    
    Under **Advanced**, you can choose to edit image tags for **ETCD**, **CoreDNS**, and **Calico**, or whether to install **OCI CCM/CSI** and **Calico**.
1. Configure Node Pools, if necessary for your environment.
1. Install Verrazzano on the cluster. Choose a **Verrazzano version** from the dropdown list. You can also expand **Advanced** to make changes to the Verrazzano Resource YAML. By default, Verrazzano is installed using the `managed-cluster` profile which enables a limited set of components on the cluster.
1. Expand **Advanced Settings** to make additional modifications to the default settings of your new cluster. 
    * **YAML Manifests**: Specify post-provisioning installations. 
    * **Cluster Networking**: configure networking and proxy settings for the cluster. 
    * **Container Registry**: Specify a private registry for your container.
1. Click **Create**. It will take a few minutes to provision all of the resources for your cluster.

When your cluster finishes provisioning, you can access it from the main **Cluster Management** page.




