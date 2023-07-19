---
title: Create OCNE Clusters running on OCI
description: "Add Oracle Cloud Native Environment self-managed clusters running on OCI to your multicluster environment"
weight: 1
draft: false
---

### Before you begin

You'll need to:

* Set up an Oracle Cloud Infrastructure (OCI) account with a compartment
* Generate an SSH key pair to use for cluster authentication

### Create a new OCNE cluster on OCI

To provision new Oracle Cloud Native Environment (OCNE) managed clusters on OCI, complete the following steps:

1. Log in to the console. To find the console URL for your cluster, refer to [Get console URLs]({{< relref "/docs/setup/access/console-urls.md" >}}) and use the `rancherURL` value.
1. Open the navigation menu and select **Cluster Management**.
1. From the left menu, select **Cloud Credentials**, and then click **Create**. Cloud credentials store the credentials for your cloud infrastructure provider.
1. Choose **Oracle**.
1. Provide a name for the cloud credential and then fill in the fields. You can find the required information in your [OCI configuration file](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#Required_Keys_and_OCIDs). Click **Create**.
1. From the left menu, select **Clusters**, and then click **Create**.
1. Select **Oracle OCNE on OCI** and provide a name for the cluster.
1. Expand **Member Roles** to add any users that you want grant access to this cluster and their permissions.
1. Expand **Labels and Annotations** to configure Kubernetes [labels](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/) and [annotations](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) for the cluster.
1. Select the cloud credentials that you created. Ensure that the appropriate Region and Compartment are selected from their drop-down lists.
1. Click **Next**.
1. Set up your network. Choose **Quick Create** to create a new virtual cloud network (VCN) configured to the specifications required for an OCNE cluster or **Existing Infrastructure** to use a VCN that's already configured in your OCI account.

    * If you choose the **Existing Infrastructure** option, then select the compartment where your VCN is located from the **VCN Compartment** drop-down list, then the VCN itself from the **Virtual Cloud Network** drop-down list. Next, select subnets within the VCN for each of the **Cloud Plane Subnet**, **Load Balancer Subnet**, and **Worker Node Subnet** drop-down lists.

    * The VCN compartment does not need to match the compartment specified in the cloud credential.
1. Click **Next**.
1. Choose a Node Image from the drop-down list.

    You can choose to override the default Node Image. Expand **OCNE Image Configuration** and provide a custom image OCID. If your custom image includes OCNE binaries, then you can select **Skip OCNE Dependency Installation** to avoid duplicates.

1. Copy or upload an SSH public key to manage authentication of the cluster. Your SSH public key is installed on the cluster nodes, enabling SSH after the cluster is created.
1. Configure the cluster control plane. Select the **OCNE Version** first because it determines which Kubernetes versions are available, then choose a **Kubernetes Version** and a **Control Plane Shape**. You can leave the rest of the options at their default setting or modify them as needed.

    Under **Advanced**, you can choose to edit image tags for **ETCD**, **CoreDNS**, and **Calico**, or whether to install **OCI CCM/CSI** and **Calico**.

1. Add node pools to your cluster. Clusters without node pools will schedule pods on control plane nodes.
1. (Optional) Install Verrazzano on the cluster. Choose a **Verrazzano version** from the drop-down list. You can also expand **Advanced** to make changes to the Verrazzano Resource YAML. By default, Verrazzano is installed using the `managed-cluster` profile which enables a limited set of components on the cluster.
1. Expand **Advanced Settings** to make additional modifications to the default settings of your new cluster.
    * **YAML Manifests**: Supply additional YAML manifests that are automatically installed after cluster creation. The total size of all additional YAML manifests may not exceed 500 KB.
    * **Cluster Networking**: Configure cluster IP ranges and proxy settings.
    * **Container Registry**: Specify a private registry for your container.
1. Click **Create**. It can take up to 30 minutes to provision all of the resources for your cluster, particularly for multi-node clusters.

When your cluster finishes provisioning, you can access it from the main **Cluster Management** page.




