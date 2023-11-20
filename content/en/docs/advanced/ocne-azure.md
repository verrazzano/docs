---
title: Create OCNE Clusters Running on Microsoft Azure
linkTitle: Create OCNE Clusters Running on Microsoft Azure
description: Configure Oracle Cloud Native Environment self-managed clusters to run on Microsoft Azure
weight: 2
draft: false
---

{{% alert title="NOTE" color="danger" %}}
This feature is experimental. It has not been thoroughly tested and is provided for informational purposes only. We make no guarantees about its safety or stability and do not recommend implementing this feature in production environments.
{{% /alert %}}

The Cluster API project provides a standard set of Kubernetes-style APIs for cluster management. Officially, Verrazzano currently only supports using Cluster API to [provision OCNE and OKE clusters on OCI]({{< relref "/docs/setup/provision-cluster" >}}).

However, you can also experiment with using the features of the Cluster API project directly to deploy OCNE clusters on Microsoft Azure.

For more information on Cluster API or Cluster API with Azure, see:

* [Kubernetes Cluster API Documentation](https://cluster-api.sigs.k8s.io/introduction.html)
* [The Cluster API Provider Azure Book](https://capz.sigs.k8s.io/introduction)
    * [Getting started with cluster-api-provider-azure](https://capz.sigs.k8s.io/topics/getting-started)

{{% alert title="NOTE" color="primary" %}}
Verrazzano and Cluster API use slightly different terminology for the same concepts:

* Admin cluster (Verrazzano) = management cluster (Cluster API) 
* Managed cluster (Verrazzano) = workload cluster (Cluster API)
{{% /alert %}}

## Prepare Azure resources

Before you can deploy a Cluster API cluster, you need to set up a few resources in Azure.

1. Install the Azure command-line interface (CLI) tool. For instructions, see [How to install the Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) in the Microsoft Azure documentation.
1. Create an Azure resource group. In the Azure CLI, run the following command:
{{< clipboard >}}
<div class="highlight">

```
$ az group create --name <ResourceGroupName> --location <location>
```
</div>
{{< /clipboard >}}
For more detailed instructions, see [Manage Azure Resource Groups by using Azure CLI](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-cli) in the Microsoft Azure documentation.
1. Create a service principal. Make sure it has the privileges it needs to create resources. This means a contributor role at minimum.  The following example creates a service principal, assigns it the contributor role, and defines its scope.
{{< clipboard >}}
<div class="highlight">

```
$ az ad sp create-for-rbac  --name myServicePrincipalName \
                            --role Contributor \
                            --scopes /subscriptions/mySubscriptionID/resourceGroups/myResourceGroupName
```
</div>
{{< /clipboard >}}
For more detailed instructions, see [Create an Azure service principal with Azure CLI](https://learn.microsoft.com/en-us/cli/azure/azure-cli-sp-tutorial-1) in the Microsoft Azure documentation.

## Set up the admin cluster

The Cluster API requires an initial cluster as a starting point to deploy its resources.

1. Install kind. Follow the instructions at [Installation](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) in the kind documentation.
1. Create a Kubernetes cluster using kind. Follow the instructions at [Quick Start: Install and/or configure a Kubernetes cluster](https://cluster-api.sigs.k8s.io/user/quick-start#install-andor-configure-a-kubernetes-cluster) in The Cluster API Book.
1. Install the clusterctl CLI tool. clusterctl manages the lifecycle operations of a cluster API admin cluster. Follow the instructions at [Quick Start: Install clusterctl](https://cluster-api.sigs.k8s.io/user/quick-start.html#install-clusterctl) in the Cluster API Book.
1. Install the Verrazzano CLI tool using the instructions at [CLI Setup]({{< relref "/docs/setup/install/prepare/cli-setup" >}}).
1. Install Verrazzano on the cluster using either the `dev` or `prod` installation profile. Follow the instructions at [Install with CLI]({{< relref "/docs/setup/install/perform/cli-installation" >}}). The `certManager` and `clusterAPI` components are required and must remain enabled.
1. On the cluster, set environment variables for the following Azure resource IDs from your Azure account and from the service principal you created:
    * Subscription ID
    * Tenant ID
    * Client ID
    * Client Secret

    For example:
{{< clipboard >}}
<div class="highlight">

```
# Azure resource  IDs
$ export AZURE_SUBSCRIPTION_ID="<SubscriptionId>"
$ export AZURE_TENANT_ID="<Tenant>"
$ export AZURE_CLIENT_ID="<AppId>"
$ export AZURE_CLIENT_SECRET="<Password>"

# Base64 encode the Azure Resource IDs
$ export AZURE_SUBSCRIPTION_ID_B64="$(echo -n "$AZURE_SUBSCRIPTION_ID" | base64 | tr -d '\n')"
$ export AZURE_TENANT_ID_B64="$(echo -n "$AZURE_TENANT_ID" | base64 | tr -d '\n')"
$ export AZURE_CLIENT_ID_B64="$(echo -n "$AZURE_CLIENT_ID" | base64 | tr -d '\n')"
$ export AZURE_CLIENT_SECRET_B64="$(echo -n "$AZURE_CLIENT_SECRET" | base64 | tr -d '\n')"

# Settings needed for AzureClusterIdentity used by the AzureCluster
$ export AZURE_CLUSTER_IDENTITY_SECRET_NAME="<cluster-identity-secret>"
$ export CLUSTER_IDENTITY_NAME="<cluster-identity>"
$ export AZURE_CLUSTER_IDENTITY_SECRET_NAMESPACE="default"
```
</div>
{{< /clipboard >}}
1. Create a secret that includes the password of the service principal identity created in Azure. This secret is referenced by the AzureClusterIdentity used by the AzureCluster.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl create secret generic "${AZURE_CLUSTER_IDENTITY_SECRET_NAME}" --from-literal=clientSecret="${AZURE_CLIENT_SECRET}" --namespace "${AZURE_CLUSTER_IDENTITY_SECRET_NAMESPACE}"
```
</div>
{{< /clipboard >}}
1. Install the Cluster API Azure infrastructure provider.
{{< clipboard >}}
<div class="highlight">

```
$ clusterctl init -n verrazzano-capi -i azure
```
</div>
{{< /clipboard >}}

    clusterctl will report when the admin cluster was successfully initialized.


## Create a managed cluster

The Cluster API uses a cluster template to deploy a predefined set of Cluster API objects and create a managed cluster.

1. Set the following environment variables so they are available to the cluster template. Update the values to reflect your own environment.
{{< clipboard >}}
<div class="highlight">

```
# Base64 encoded SSH key for node access
$ export AZURE_SSH_PUBLIC_KEY_B64="<sshKey>"
  
# Select VM types.
$ export AZURE_CONTROL_PLANE_MACHINE_TYPE="Standard_D2s_v3"
$ export AZURE_NODE_MACHINE_TYPE="Standard_D2s_v3"
 
# [Optional] Select resource group. The default value is ${CLUSTER_NAME}.
$ export AZURE_RESOURCE_GROUP="<resourceGroupName>
 
# Name of the Azure datacenter location. Change this value to your desired location.
$ export AZURE_LOCATION="<location>"
 
# Cluster name info
$ export CLUSTER_NAME="capi-quickstart"
$ export KUBERNETES_VERSION="<k8sVersion>"
$ export NAMESPACE="default"
$ export CONTROL_PLANE_MACHINE_COUNT="1"
$ export WORKER_MACHINE_COUNT="1"
```
</div>
{{< /clipboard >}}

1. Copy the cluster template and save it locally as `azure-capi.yaml`.
    <details>
    <summary><b>Click here for the cluster template</b></summary>
    {{< clipboard >}}
<div class="highlight">

```
apiVersion: cluster.x-k8s.io/v1beta1
kind: Cluster
metadata:
  name: ${CLUSTER_NAME}
  namespace: default
spec:
  clusterNetwork:
    pods:
      cidrBlocks:
        - 192.168.0.0/16
  controlPlaneRef:
    apiVersion: controlplane.cluster.x-k8s.io/v1beta1
    kind: OCNEControlPlane
    name: ${CLUSTER_NAME}-control-plane
  infrastructureRef:
    apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
    kind: AzureCluster
    name: ${CLUSTER_NAME}
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
kind: AzureCluster
metadata:
  name: ${CLUSTER_NAME}
  namespace: default
spec:
  identityRef:
    apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
    kind: AzureClusterIdentity
    name: ${CLUSTER_IDENTITY_NAME}
  location: ${AZURE_LOCATION}
  networkSpec:
    subnets:
      - name: control-plane-subnet
        role: control-plane
      - name: node-subnet
        role: node
    vnet:
      name: ${AZURE_VNET_NAME:=${CLUSTER_NAME}-vnet}
  resourceGroup: ${AZURE_RESOURCE_GROUP:=${CLUSTER_NAME}}
  subscriptionID: ${AZURE_SUBSCRIPTION_ID}
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
kind: AzureMachineTemplate
metadata:
  name: ${CLUSTER_NAME}-control-plane
  namespace: default
spec:
  template:
    spec:
      image:
        marketplace:
          publisher: "Oracle"
          offer: "Oracle-Linux"
          sku: "ol88-lvm-gen2"
          version: "8.8.3"
      dataDisks:
        - diskSizeGB: 256
          lun: 0
          nameSuffix: etcddisk
      osDisk:
        diskSizeGB: 128
        osType: Linux
      sshPublicKey: ${AZURE_SSH_PUBLIC_KEY_B64:=""}
      vmSize: ${AZURE_CONTROL_PLANE_MACHINE_TYPE}
---
apiVersion: cluster.x-k8s.io/v1beta1
kind: MachineDeployment
metadata:
  name: ${CLUSTER_NAME}-md-0
  namespace: default
spec:
  clusterName: ${CLUSTER_NAME}
  replicas: ${WORKER_MACHINE_COUNT}
  selector:
    matchLabels: null
  template:
    spec:
      bootstrap:
        configRef:
          apiVersion: bootstrap.cluster.x-k8s.io/v1beta1
          kind: OCNEConfigTemplate
          name: ${CLUSTER_NAME}-md-0
      clusterName: ${CLUSTER_NAME}
      infrastructureRef:
        apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
        kind: AzureMachineTemplate
        name: ${CLUSTER_NAME}-md-0
      version: ${KUBERNETES_VERSION}
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
kind: AzureMachineTemplate
metadata:
  name: ${CLUSTER_NAME}-md-0
  namespace: default
spec:
  template:
    spec:
      image:
        marketplace:
          publisher: "Oracle"
          offer: "Oracle-Linux"
          sku: "ol88-lvm-gen2"
          version: "8.8.3"
      osDisk:
        diskSizeGB: 128
        osType: Linux
      sshPublicKey: ${AZURE_SSH_PUBLIC_KEY_B64:=""}
      vmSize: ${AZURE_NODE_MACHINE_TYPE}
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
kind: AzureClusterIdentity
metadata:
  labels:
    clusterctl.cluster.x-k8s.io/move-hierarchy: "true"
  name: ${CLUSTER_IDENTITY_NAME}
  namespace: default
spec:
  allowedNamespaces: {}
  clientID: ${AZURE_CLIENT_ID}
  clientSecret:
    name: ${AZURE_CLUSTER_IDENTITY_SECRET_NAME}
    namespace: ${AZURE_CLUSTER_IDENTITY_SECRET_NAMESPACE}
  tenantID: ${AZURE_TENANT_ID}
  type: ServicePrincipal
---
apiVersion: controlplane.cluster.x-k8s.io/v1alpha1
kind: OCNEControlPlane
metadata:
  name: ${CLUSTER_NAME}-control-plane
  namespace: default
spec:
  moduleOperator:
    enabled: true
  verrazzanoPlatformOperator:
    enabled: true
  controlPlaneConfig:
    clusterConfiguration:
      apiServer:
        extraArgs:
          cloud-provider: external
        certSANs:
          - localhost
          - 127.0.0.1
      dns:
        imageRepository: ${OCNE_IMAGE_REPOSITORY=container-registry.oracle.com}/${OCNE_IMAGE_PATH=olcne}
        imageTag: ${DNS_TAG=v1.9.3}
      etcd:
        local:
          imageRepository: ${OCNE_IMAGE_REPOSITORY=container-registry.oracle.com}/${OCNE_IMAGE_PATH=olcne}
          imageTag: ${ETCD_TAG=3.5.6}
      controllerManager:
        extraArgs:
          cloud-provider: external
      networking: {}
      scheduler: {}
      imageRepository: ${OCNE_IMAGE_REPOSITORY=container-registry.oracle.com}/${OCNE_IMAGE_PATH=olcne}
    files:
      - contentFrom:
          secret:
            key: control-plane-azure.json
            name: ${CLUSTER_NAME}-control-plane-azure-json
        owner: root:root
        path: /etc/kubernetes/azure.json
        permissions: "0644"
    initConfiguration:
      nodeRegistration:
        criSocket: /var/run/crio/crio.sock
        kubeletExtraArgs:
          cloud-provider: external
        name: '{{ local_hostname }}'
    joinConfiguration:
      discovery: {}
      nodeRegistration:
        criSocket: /var/run/crio/crio.sock
        kubeletExtraArgs:
          cloud-provider: external
        name: '{{ local_hostname }}'
    preOCNECommands:
      - hostnamectl set-hostname "{{ ds.meta_data.hostname }}"
      - echo "::1         ipv6-localhost ipv6-loopback localhost6 localhost6.localdomain6"
        >/etc/hosts
      - echo "127.0.0.1   {{ ds.meta_data.hostname }} {{ local_hostname }} localhost
        localhost.localdomain localhost4 localhost4.localdomain4" >>/etc/hosts
    users:
      - name: opc
        sudo: ALL=(ALL) NOPASSWD:ALL
  machineTemplate:
    infrastructureRef:
      apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
      kind: AzureMachineTemplate
      name: ${CLUSTER_NAME}-control-plane
      namespace: default
  replicas: ${CONTROL_PLANE_MACHINE_COUNT}
  version: ${KUBERNETES_VERSION}
---
apiVersion: bootstrap.cluster.x-k8s.io/v1alpha1
kind: OCNEConfigTemplate
metadata:
  name: ${CLUSTER_NAME}-md-0
  namespace: default
spec:
  template:
    spec:
      clusterConfiguration:
        imageRepository: ${OCNE_IMAGE_REPOSITORY=container-registry.oracle.com}/${OCNE_IMAGE_PATH=olcne}
      joinConfiguration:
        nodeRegistration:
          kubeletExtraArgs:
            cloud-provider: external
          name: '{{ local_hostname }}'
      preOCNECommands:
        - hostnamectl set-hostname "{{ ds.meta_data.hostname }}"
        - echo "::1         ipv6-localhost ipv6-loopback localhost6 localhost6.localdomain6"
          >/etc/hosts
        - echo "127.0.0.1   {{ ds.meta_data.hostname }} {{ local_hostname }} localhost
          localhost.localdomain localhost4 localhost4.localdomain4" >>/etc/hosts
      users:
        - name: opc
          sudo: ALL=(ALL) NOPASSWD:ALL
```
</div>
    {{< /clipboard >}}
    </details>
1. Generate and apply the template by running the following command:
{{< clipboard >}}
<div class="highlight">

```
$ clusterctl generate yaml --from azure-capi.yaml | kubectl apply -f -
```
</div>
{{< /clipboard >}}

To view the status of the cluster and its resources, run:
{{< clipboard >}}
<div class="highlight">

```
$ clusterctl describe cluster $CLUSTER_NAME
```
</div>
{{< /clipboard >}}

To get the `kubeconfig` file, run:
{{< clipboard >}}
<div class="highlight">

```
$ clusterctl get kubeconfig ${CLUSTER_NAME} > ${CLUSTER_NAME}.kubeconfig
```
</div>
{{< /clipboard >}}


## Finish cluster configuration 

After the cluster resources are created, you must perform some additional steps to finish the configuration of the cluster.

1. Install a cloud controller manager (CCM). A CCM is necessary when deploying cloud resources such as load balancers. 
{{< clipboard >}}
<div class="highlight">

```
$ helm install --kubeconfig=./${CLUSTER_NAME}.kubeconfig --repo https://raw.githubusercontent.com/kubernetes-sigs/cloud-provider-azure/master/helm/repo cloud-provider-azure --generate-name --set infra.clusterName=clusterName --set cloudControllerManager.clusterCIDR="192.168.0.0/16" --set cloudControllerManager.caCertDir=/etc/pki/ca-trust
```
</div>
{{< /clipboard >}}
1. Install a container network interface (CNI). The following example uses the Calico CNI.
{{< clipboard >}}
<div class="highlight">

```
$ helm repo add projectcalico https://docs.tigera.io/calico/charts --kubeconfig=./${CLUSTER_NAME}.kubeconfig && \
$ helm install calico projectcalico/tigera-operator --kubeconfig=./${CLUSTER_NAME}.kubeconfig -f https://raw.githubusercontent.com/kubernetes-sigs/cluster-api-provider-azure/main/templates/addons/calico/values.yaml --namespace tigera-operator --create-namespace
```
</div>
{{< /clipboard >}}

Your admin cluster and first managed cluster are now up and running and ready to deploy applications. You can add more managed clusters as needed.

For more information, refer to the documentation for Cluster API and Cluster API Azure:

* [Kubernetes Cluster API Documentation](https://cluster-api.sigs.k8s.io/introduction.html)
* [The Cluster API Provider Azure Book](https://capz.sigs.k8s.io/introduction)

## Troubleshoot the deployment

If the deployment of the Azure resources fails, then you can check the following log files to diagnose the issue:

The Azure cluster controller provider logs:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl logs -n verrazzano-capi -l cluster.x-k8s.io/provider=infrastructure-azure
```
</div>
{{< /clipboard >}}
The OCNE control plane provider logs:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl logs -n verrazzano-capi -l cluster.x-k8s.io/provider=control-plane-ocne
```
</div>
{{< /clipboard >}}

**NOTE**: If a pod enters a `CrashLoopBackOff` state, then you can either restart the deployment or wait for the state to run its course. This is a known issue that should not affect the deployment of your cluster.

## Delete the clusters

1. Delete the managed clusters.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl delete cluster $CLUSTER_NAME
```
</div>
{{< /clipboard >}}
1. Delete the admin cluster.
{{< clipboard >}}
<div class="highlight">

```
$ kind delete cluster
```
</div>
{{< /clipboard >}}

Do not use `kubectl delete -f capi-quickstart.yaml` to delete the entire cluster template at once because it might leave behind pending resources that you need to clean up manually.