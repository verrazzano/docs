---
title: Create OCNE Clusters Running on VMware vSphere
linkTitle: Create OCNE Clusters Running on VMware vSphere
description: Configure Oracle Cloud Native Environment self-managed clusters to run on VMware vSphere
weight: 3
draft: false
---

{{% alert title="NOTE" color="danger" %}}
This feature is experimental. It has not been thoroughly tested and is provided for informational purposes only. We make no guarantees about its safety or stability and do not recommend implementing this feature in production environments.
{{% /alert %}}

The Cluster API project provides a standard set of Kubernetes-style APIs for cluster management. Officially, Verrazzano currently only supports using Cluster API to [provision OCNE and OKE clusters on OCI]({{< relref "/docs/setup/provision-cluster" >}}).

However, you can also experiment with using the features of the Cluster API project directly to deploy OCNE clusters on VMware vSphere.

For more information on Cluster API or Cluster API with vSphere, see:

* [Kubernetes Cluster API Documentation](https://cluster-api.sigs.k8s.io/introduction.html)
* [Kubernetes Cluster API Provider vSphere](https://github.com/kubernetes-sigs/cluster-api-provider-vsphere)
    * [Getting started with Cluster API Provider vSphere](https://github.com/kubernetes-sigs/cluster-api-provider-vsphere/blob/main/docs/getting_started.md)

## Before you begin


If you have an existing vSphere environment, you can ignore **Set up a VMware Software-Defined Data Center** and start from [Prepare the VM environment]({{< relref "#prepare-the-vm-environment" >}}). Confirm that your environment meets the requirements as specified at [Cluster API Provider vSphere: Install Requirements](https://github.com/kubernetes-sigs/cluster-api-provider-vsphere/blob/main/docs/getting_started.md#install-requirements)

Otherwise, create a vSphere environment. We recommend using the Oracle Cloud VMware Solution as described in [Set up a VMware Software-Defined Data Center]({{< relref "#set-up-a-vmware-software-defined-data-center" >}}). It deploys a VMware software-defined data center (SDDC) on Oracle Cloud Infrastructure (OCI) and then integrates it with other Oracle services running on Oracle Cloud. This solution was developed in partnership with VMware to provide an environment that adheres to best practices recommended by VMware.

For more information on the Oracle Cloud VMware Solution, see [Deploy a highly available VMware-based SDDC to the cloud](https://docs.oracle.com/en/solutions/deploy-vmware-sddc-oci/index.html#GUID-860B8193-4612-4589-81DB-A8F63ADBD0F4) in the Oracle Help Architecture Center.

## Set up a VMware Software-Defined Data Center

{{% alert title="NOTE" color="primary" %}}
Skip this section if you have configured a vSphere environment or a VMware SDDC already.
{{% /alert %}}

Use the Oracle Cloud VMware Solution to rapidly create a VMware SDDC. 

1. Set up a virtual cloud network (VCN). You can choose to use an existing VCN or let the Oracle Cloud VMware Solution create its own VCN as part of the SDDC provisioning process. If you use an existing VCN, then make sure it meets the requirements defined in [Prepare Your Deployment](https://docs.oracle.com/en/solutions/deploy-vmware-sddc-oci/deploy-sddc-cloud1.html#GUID-EC84353E-01A8-4F41-A43A-10A47C66611C) in the Oracle Help Architecture Center.

1. Deploy the SDDC. To request a new VMware SDDC on OCI, follow the instructions at [Deploy the SDDC](https://docs.oracle.com/en/solutions/deploy-vmware-sddc-oci/deploy-sddc-cloud1.html#GUID-8D3BD5B0-F603-4529-903F-641C24935720) in the Oracle Help Architecture Center.
1. Ensure that the various components were created successfully. Follow the instructions at [Monitor the SDDC Creation Process](https://docs.oracle.com/en/solutions/deploy-vmware-sddc-oci/deploy-sddc-cloud1.html#GUID-E170AD8F-7E51-44C6-93D9-DC332F3D8025) in the Oracle Help Architecture Center.


## Prepare the VM environment

1. Download an Oracle Linux 8 ISO image from [Oracle Linux Installation Media](https://yum.oracle.com/oracle-linux-isos.html).

1. Deploy a VM by following the instructions at [Create a Virtual Machine with the New Virtual Machine Wizard](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.vm_admin.doc/GUID-AE8AFBF1-75D1-4172-988C-378C35C9FAF2.html?hWord=N4IghgNiBcIEZgM4FMAEA3AtiAvkA) in the vSphere documentation.
1. Upload the Oracle Linux 8 ISO image to vSphere. Use the steps at [Upload ISO Image Installation Media for a Guest Operating System](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.vm_admin.doc/GUID-492D6904-7471-4D66-9555-9466CCCA6931.html) in the vSphere documentation.
1. Install cloud-init on the VM.
{{< clipboard >}}
<div class="highlight">

```
$ sudo yum install -y cloud-init
```
</div>
{{< /clipboard >}}
1. Initialize cloud-init.
{{< clipboard >}}
<div class="highlight">

```
$ cloud-init init --local
```
</div>
{{< /clipboard >}}
When cloud-init is successfully configured, it returns a message similar to the following:
{{< clipboard >}}
<div class="highlight">

```
$ cloud-init v. 20.1.0011 running 'init-local' at Fri, 01 Apr 2022 01:26:11 +0000. Up 38.70 seconds.
```
</div>
{{< /clipboard >}}
1. Shut down the VM.
1. Convert the VM into a template and name it `OL8-Base-Template`. Follow the instructions at [Clone a Virtual Machine to a Template](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.vm_admin.doc/GUID-5B3737CC-28DB-4334-BD18-6E12011CDC9F.html) in the vSphere documentation.

## Set up the admin cluster

The Cluster API requires an initial cluster as a starting point to deploy its resources.

1. Install kind. Follow the instructions at [Installation](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) in the kind documentation.

1. Create a Kubernetes cluster using kind. This cluster must be accessible by the VMware SDDC. Follow the instructions at [Quick Start: Install and/or configure a Kubernetes cluster](https://cluster-api.sigs.k8s.io/user/quick-start#install-andor-configure-a-kubernetes-cluster) in The Cluster API Book.
1. Install the clusterctl CLI tool. clusterctl manages the lifecycle operations of a cluster API admin cluster. Follow instructions at [Quick Start: Install clusterctl](https://cluster-api.sigs.k8s.io/user/quick-start.html#install-clusterctl) in the Cluster API Book.
1. Install the Verrazzano CLI tool using the instructions at [CLI Setup]({{< relref "/docs/setup/install/prepare/cli-setup" >}}).
1. Install Verrazzano on the cluster using either the `dev` or `prod` profile. Follow the instructions at [Install with CLI]({{< relref "/docs/setup/install/perform/cli-installation" >}}).
1. On the cluster, set the following vSphere environment variables. Update the values to reflect your own environment.
{{< clipboard >}}
<div class="highlight">

```
$ export VSPHERE_PASSWORD="<vmware-password>"
$ export VSPHERE_USERNAME="administrator@vsphere.local"
$ export VSPHERE_SERVER="<IP address or FQDN>"
$ export VSPHERE_DATACENTER="<SDDC-Datacenter>"
$ export VSPHERE_DATASTORE="<vSAN-Datastore>"	
$ export VSPHERE_NETWORK="workload"
$ export VSPHERE_RESOURCE_POOL="*/Resources/Workload"
$ export VSPHERE_FOLDER="<folder-name>"
$ export VSPHERE_TEMPLATE="OL8-Base-Template"
$ export VSPHERE_SSH_AUTHORIZED_KEY="<Public-SSH-Authorized-Key>"
$ export VSPHERE_TLS_THUMBPRINT="<SHA1 thumbprint of vCenter certificate>"
$ export VSPHERE_STORAGE_POLICY=""
$ export CONTROL_PLANE_ENDPOINT_IP="<IP address or FQDN>"
```
</div>
{{< /clipboard >}}
For information on the values of the environment variables, see [Configuring and installing Cluster API Provider vSphere in a management cluster](https://github.com/kubernetes-sigs/cluster-api-provider-vsphere/blob/main/docs/getting_started.md#configuring-and-installing-cluster-api-provider-vsphere-in-a-management-cluster) in the Cluster API Provider vSphere documentation.
1. Install the Cluster API Provider vSphere to initialize the admin cluster.
{{< clipboard >}}
<div class="highlight">

```
$ clusterctl init -n verrazzano-capi -i vsphere
```
</div>
{{< /clipboard >}}

clusterctl will report when the admin cluster was successfully initialized.

## Create a managed cluster

The Cluster API uses a cluster template to deploy a predefined set of Cluster API objects and create a managed cluster.

1. Copy the cluster template provided below and save it locally as `vsphere-capi.yaml`.
    <details>
    <summary><b>Click here to expand and see the cluster template</b></summary>
    {{< clipboard >}}
<div class="highlight">

```
apiVersion: cluster.x-k8s.io/v1beta1
kind: Cluster
metadata:
  labels:
    cluster.x-k8s.io/cluster-name: ${CLUSTER_NAME}
  name: ${CLUSTER_NAME}
  namespace: ${NAMESPACE}
spec:
  clusterNetwork:
    pods:
      cidrBlocks:
        - ${POD_CIDR=192.168.0.0/16}
    serviceDomain: cluster.local
    services:
      cidrBlocks:
        - ${CLUSTER_CIDR=10.128.0.0/12}
  controlPlaneRef:
    apiVersion: controlplane.cluster.x-k8s.io/v1alpha1
    kind: OCNEControlPlane
    name: ${CLUSTER_NAME}-control-plane
    namespace: ${NAMESPACE}
  infrastructureRef:
    apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
    kind: VSphereCluster
    name: ${CLUSTER_NAME}
    namespace: ${NAMESPACE}
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
kind: VSphereCluster
metadata:
  name: ${CLUSTER_NAME}
  namespace: ${NAMESPACE}
spec:
  controlPlaneEndpoint:
    host: ${CONTROL_PLANE_ENDPOINT_IP}
    port: 6443
  identityRef:
    kind: Secret
    name: ${CLUSTER_NAME}
  server: ${VSPHERE_SERVER}
  thumbprint: '${VSPHERE_TLS_THUMBPRINT}'
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
kind: VSphereMachineTemplate
metadata:
  name: ${CLUSTER_NAME}-control-plane
  namespace: ${NAMESPACE}
spec:
  template:
    spec:
      cloneMode: linkedClone
      datacenter: ${VSPHERE_DATACENTER=oci-w01dc}
      datastore: ${VSPHERE_DATASTORE=vsanDatastore}
      diskGiB: ${VSPHERE_DISK=200}
      folder: ${VSPHERE_FOLDER=CAPI}
      memoryMiB: ${VSPHERE_MEMORY=32384}
      network:
        devices:
          - dhcp4: true
            networkName: "${VSPHERE_NETWORK=workload}"
      numCPUs: ${VSPHERE_CPU=4}
      os: Linux
      resourcePool: '${VSPHERE_RESOURCE_POOL=*/Resources/Workload}'
      server: '${VSPHERE_SERVER=11.0.11.130}'
      storagePolicyName: ${VSPHERE_STORAGE_POLICY=""}
      template: ${VSPHERE_TEMPLATE=OL8-Base-Template}
      thumbprint: '${VSPHERE_TLS_THUMBPRINT}'
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
kind: VSphereMachineTemplate
metadata:
  name: ${CLUSTER_NAME}-md-0
  namespace: ${NAMESPACE}
spec:
  template:
    spec:
      cloneMode: linkedClone
      datacenter: ${VSPHERE_DATACENTER=oci-w01dc}
      datastore: ${VSPHERE_DATASTORE=vsanDatastore}
      diskGiB: ${VSPHERE_DISK=200}
      folder: ${VSPHERE_FOLDER=CAPI}
      memoryMiB: ${VSPHERE_MEMORY=32384}
      network:
        devices:
          - dhcp4: true
            networkName: "${VSPHERE_NETWORK=workload}"
      numCPUs: ${VSPHERE_CPU=4}
      os: Linux
      resourcePool: '${VSPHERE_RESOURCE_POOL=*/Resources/Workload}'
      server: '${VSPHERE_SERVER=11.0.11.130}'
      storagePolicyName: ${VSPHERE_STORAGE_POLICY=""}
      template: ${VSPHERE_TEMPLATE=OL8-Base-Template}
      thumbprint: '${VSPHERE_TLS_THUMBPRINT}'
---
apiVersion: controlplane.cluster.x-k8s.io/v1alpha1
kind: OCNEControlPlane
metadata:
  name: ${CLUSTER_NAME}-control-plane
  namespace: ${NAMESPACE}
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
      - content: |
          apiVersion: v1
          kind: Pod
          metadata: 
            creationTimestamp: null
            name: kube-vip
            namespace: kube-system
          spec: 
            containers: 
            - args: 
              - manager
              env: 
              - name: cp_enable
                value: "true"
              - name: vip_interface
                value: ""
              - name: address
                value: ${CONTROL_PLANE_ENDPOINT_IP}
              - name: port
                value: "6443"
              - name: vip_arp
                value: "true"
              - name: vip_leaderelection
                value: "true"
              - name: vip_leaseduration
                value: "15"
              - name: vip_renewdeadline
                value: "10"
              - name: vip_retryperiod
                value: "2"
              image: ghcr.io/kube-vip/kube-vip:v0.5.11
              imagePullPolicy: IfNotPresent
              name: kube-vip
              resources: {}
              securityContext: 
                capabilities: 
                  add: 
                  - NET_ADMIN
                  - NET_RAW
              volumeMounts: 
              - mountPath: /etc/kubernetes/admin.conf
                name: kubeconfig
            hostAliases: 
            - hostnames: 
              - kubernetes
              ip: 127.0.0.1
            hostNetwork: true
            volumes: 
            - hostPath: 
                path: /etc/kubernetes/admin.conf
                type: FileOrCreate
              name: kubeconfig
          status: {}
        owner: root:root
        path: /etc/kubernetes/manifests/kube-vip.yaml
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
    verbosity: 9
    preOCNECommands:
      - hostnamectl set-hostname "{{ ds.meta_data.hostname }}"
      - echo "::1         ipv6-localhost ipv6-loopback localhost6 localhost6.localdomain6"
        >/etc/hosts
      - echo "127.0.0.1   {{ ds.meta_data.hostname }} {{ local_hostname }} localhost
        localhost.localdomain localhost4 localhost4.localdomain4" >>/etc/hosts
    users:
      - name: opc
        sshAuthorizedKeys:
          - ${VSPHERE_SSH_AUTHORIZED_KEY}
        sudo: ALL=(ALL) NOPASSWD:ALL
  machineTemplate:
    infrastructureRef:
      apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
      kind: VSphereMachineTemplate
      name: ${CLUSTER_NAME}-control-plane
      namespace: ${NAMESPACE}
  replicas: ${CONTROL_PLANE_MACHINE_COUNT=1}
  version: ${KUBERNETES_VERSION=v1.26.6}
---
apiVersion: bootstrap.cluster.x-k8s.io/v1alpha1
kind: OCNEConfigTemplate
metadata:
  name: ${CLUSTER_NAME}-md-0
  namespace: ${NAMESPACE}
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
      verbosity: 9
      preOCNECommands:
        - hostnamectl set-hostname "{{ ds.meta_data.hostname }}"
        - echo "::1         ipv6-localhost ipv6-loopback localhost6 localhost6.localdomain6"
          >/etc/hosts
        - echo "127.0.0.1   {{ ds.meta_data.hostname }} {{ local_hostname }} localhost
          localhost.localdomain localhost4 localhost4.localdomain4" >>/etc/hosts
      users:
        - name: opc
          sshAuthorizedKeys:
            - ${VSPHERE_SSH_AUTHORIZED_KEY}
          sudo: ALL=(ALL) NOPASSWD:ALL
---
apiVersion: cluster.x-k8s.io/v1beta1
kind: MachineDeployment
metadata:
  labels:
    cluster.x-k8s.io/cluster-name: ${CLUSTER_NAME}
  name: ${CLUSTER_NAME}-md-0
  namespace: ${NAMESPACE}
spec:
  clusterName: ${CLUSTER_NAME}
  replicas: ${NODE_MACHINE_COUNT=3}
  selector:
    matchLabels: {}
  template:
    metadata:
      labels:
        cluster.x-k8s.io/cluster-name: ${CLUSTER_NAME}
    spec:
      bootstrap:
        configRef:
          apiVersion: bootstrap.cluster.x-k8s.io/v1alpha1
          kind: OCNEConfigTemplate
          name: ${CLUSTER_NAME}-md-0
      clusterName: ${CLUSTER_NAME}
      infrastructureRef:
        apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
        kind: VSphereMachineTemplate
        name: ${CLUSTER_NAME}-md-0
      version: ${KUBERNETES_VERSION=v1.26.6}
---
apiVersion: addons.cluster.x-k8s.io/v1beta1
kind: ClusterResourceSet
metadata:
  name: ${CLUSTER_NAME}-crs-0
  namespace: ${NAMESPACE}
spec:
  clusterSelector:
    matchLabels:
      cluster.x-k8s.io/cluster-name: ${CLUSTER_NAME}
  resources:
    - kind: Secret
      name: ${CLUSTER_NAME}-vsphere-csi-controller
    - kind: ConfigMap
      name: ${CLUSTER_NAME}-vsphere-csi-controller-role
    - kind: ConfigMap
      name: ${CLUSTER_NAME}-vsphere-csi-controller-binding
    - kind: Secret
      name: ${CLUSTER_NAME}-csi-vsphere-config
    - kind: ConfigMap
      name: csi.vsphere.vmware.com
    - kind: ConfigMap
      name: vsphere-csi-controller-sa
    - kind: ConfigMap
      name: vsphere-csi-node-sa
    - kind: ConfigMap
      name: ${CLUSTER_NAME}-vsphere-csi-node-cluster-role
    - kind: ConfigMap
      name: ${CLUSTER_NAME}-vsphere-csi-node-cluster-role-binding
    - kind: ConfigMap
      name: ${CLUSTER_NAME}-vsphere-csi-node-role
    - kind: ConfigMap
      name: ${CLUSTER_NAME}-vsphere-csi-node-binding
    - kind: ConfigMap
      name: ${CLUSTER_NAME}-internal-feature-states.csi.vsphere.vmware.com
    - kind: ConfigMap
      name: ${CLUSTER_NAME}-vsphere-csi-controller-service
    - kind: ConfigMap
      name: ${CLUSTER_NAME}-vsphere-csi-controller
    - kind: ConfigMap
      name: ${CLUSTER_NAME}-vsphere-csi-node
    - kind: ConfigMap
      name: ${CLUSTER_NAME}-vsphere-csi-node-windows
    - kind: Secret
      name: ${CLUSTER_NAME}-cloud-controller-manager
    - kind: Secret
      name: ${CLUSTER_NAME}-cloud-provider-vsphere-credentials
    - kind: ConfigMap
      name: ${CLUSTER_NAME}-cpi-manifests
  strategy: Reconcile
---
apiVersion: v1
kind: Secret
metadata:
  name: ${CLUSTER_NAME}
  namespace: ${NAMESPACE}
stringData:
  password: ${VSPHERE_PASSWORD}
  username: ${VSPHERE_USERNAME}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${CLUSTER_NAME}-vsphere-csi-controller
  namespace: ${NAMESPACE}
data:
  data: |
    apiVersion: v1
    kind: ServiceAccount
    metadata: 
      name: vsphere-csi-controller
      namespace: kube-system
---
apiVersion: v1
data:
  data: |
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata: 
      name: vsphere-csi-controller-role
    rules: 
    - apiGroups: [""]
      resources: ["nodes", "pods", "configmaps"]
      verbs: ["get", "list", "watch"]
    - apiGroups: [""]
      resources: ["persistentvolumeclaims"]
      verbs: ["get", "list", "watch", "update"]
    - apiGroups: [""]
      resources: ["persistentvolumeclaims/status"]
      verbs: ["patch"]
    - apiGroups: [""]
      resources: ["persistentvolumes"]
      verbs: ["get", "list", "watch", "create", "update", "delete", "patch"]
    - apiGroups: [""]
      resources: ["events"]
      verbs: ["get", "list", "watch", "create", "update", "patch"]
    - apiGroups: ["coordination.k8s.io"]
      resources: ["leases"]
      verbs: ["get", "watch", "list", "delete", "update", "create"]
    - apiGroups: ["storage.k8s.io"]
      resources: ["storageclasses", "csinodes"]
      verbs: ["get", "list", "watch"]
    - apiGroups: ["storage.k8s.io"]
      resources: ["volumeattachments"]
      verbs: ["get", "list", "watch", "patch"]
    - apiGroups: ["cns.vmware.com"]
      resources: ["triggercsifullsyncs"]
      verbs: ["create", "get", "update", "watch", "list"]
    - apiGroups: ["cns.vmware.com"]
      resources: ["cnsvspherevolumemigrations"]
      verbs: ["create", "get", "list", "watch", "update", "delete"]
    - apiGroups: ["apiextensions.k8s.io"]
      resources: ["customresourcedefinitions"]
      verbs: ["get", "create", "update"]
    - apiGroups: ["storage.k8s.io"]
      resources: ["volumeattachments/status"]
      verbs: ["patch"]
    - apiGroups: ["cns.vmware.com"]
      resources: ["cnsvolumeoperationrequests"]
      verbs: ["create", "get", "list", "update", "delete"]
    - apiGroups: [ "snapshot.storage.k8s.io" ]
      resources: [ "volumesnapshots" ]
      verbs: [ "get", "list" ]
    - apiGroups: [ "snapshot.storage.k8s.io" ]
      resources: [ "volumesnapshotclasses" ]
      verbs: [ "watch", "get", "list" ]
    - apiGroups: [ "snapshot.storage.k8s.io" ]
      resources: [ "volumesnapshotcontents" ]
      verbs: [ "create", "get", "list", "watch", "update", "delete", "patch"]
    - apiGroups: [ "snapshot.storage.k8s.io" ]
      resources: [ "volumesnapshotcontents/status" ]
      verbs: [ "update", "patch" ]
    - apiGroups: [ "cns.vmware.com" ]
      resources: [ "csinodetopologies" ]
      verbs: ["get", "update", "watch", "list"]
kind: ConfigMap
metadata:
  name: ${CLUSTER_NAME}-vsphere-csi-controller-role
  namespace: ${NAMESPACE}
---
apiVersion: v1
data:
  data: |
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata: 
      name: vsphere-csi-controller-binding
    roleRef: 
      apiGroup: rbac.authorization.k8s.io
      kind: ClusterRole
      name: vsphere-csi-controller-role
    subjects: 
    - kind: ServiceAccount
      name: vsphere-csi-controller
      namespace: kube-system
kind: ConfigMap
metadata:
  name: ${CLUSTER_NAME}-vsphere-csi-controller-binding
  namespace: ${NAMESPACE}
---
apiVersion: v1
kind: Secret
metadata:
  name: ${CLUSTER_NAME}-csi-vsphere-config
  namespace: ${NAMESPACE}
stringData:
  data: |
    apiVersion: v1
    kind: Secret
    metadata: 
      name: csi-vsphere-config
      namespace: kube-system
    stringData: 
      csi-vsphere.conf: |+
        [Global]
        thumbprint = "${VSPHERE_TLS_THUMBPRINT}"
        cluster-id = "${NAMESPACE}/${CLUSTER_NAME}"

        [VirtualCenter "${VSPHERE_SERVER}"]
        insecure-flag = "true"
        user = "${VSPHERE_USERNAME}"
        password = "${VSPHERE_PASSWORD}"
        datacenters = "${VSPHERE_DATACENTER}"
        targetvSANFileShareDatastoreURLs = "${VSPHERE_DATASTORE_URL_SAN}"

        [Network]
        public-network = "${VSPHERE_NETWORK=workload}"

    type: Opaque
type: addons.cluster.x-k8s.io/resource-set
---
apiVersion: v1
data:
  data: |
    apiVersion: storage.k8s.io/v1
    kind: CSIDriver
    metadata:
      name: csi.vsphere.vmware.com
    spec:
      attachRequired: true
      podInfoOnMount: false
kind: ConfigMap
metadata:
  name: csi.vsphere.vmware.com
  namespace: ${NAMESPACE}
---
apiVersion: v1
data:
  data: |
    kind: ServiceAccount
    apiVersion: v1
    metadata:
      name: vsphere-csi-controller
      namespace: kube-system
kind: ConfigMap
metadata:
  name: vsphere-csi-controller-sa
  namespace: ${NAMESPACE}
---
apiVersion: v1
data:
  data: |
    kind: ServiceAccount
    apiVersion: v1
    metadata:
      name: vsphere-csi-node
      namespace: kube-system
kind: ConfigMap
metadata:
  name: vsphere-csi-node-sa
  namespace: ${NAMESPACE}
---
apiVersion: v1
data:
  data: |
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata: 
      name: vsphere-csi-node-cluster-role
    rules: 
      - apiGroups: ["cns.vmware.com"]
        resources: ["csinodetopologies"]
        verbs: ["create", "watch", "get", "patch"]
      - apiGroups: [""]
        resources: ["nodes"]
        verbs: ["get"]
kind: ConfigMap
metadata:
  name: ${CLUSTER_NAME}-vsphere-csi-node-cluster-role
  namespace: ${NAMESPACE}
---
apiVersion: v1
data:
  data: |
    kind: ClusterRoleBinding
    apiVersion: rbac.authorization.k8s.io/v1
    metadata:
      name: vsphere-csi-node-cluster-role-binding
    subjects:
      - kind: ServiceAccount
        name: vsphere-csi-node
        namespace: kube-system
    roleRef:
      kind: ClusterRole
      name: vsphere-csi-node-cluster-role
      apiGroup: rbac.authorization.k8s.io
kind: ConfigMap
metadata:
  name: ${CLUSTER_NAME}-vsphere-csi-node-cluster-role-binding
  namespace: ${NAMESPACE}
---
apiVersion: v1
data:
  data: |
    kind: Role
    apiVersion: rbac.authorization.k8s.io/v1
    metadata:
      name: vsphere-csi-node-role
      namespace: kube-system
    rules:
      - apiGroups: [""]
        resources: ["configmaps"]
        verbs: ["get", "list", "watch"]
kind: ConfigMap
metadata:
  name: ${CLUSTER_NAME}-vsphere-csi-node-role
  namespace: ${NAMESPACE}
---
apiVersion: v1
data:
  data: |
    kind: RoleBinding
    apiVersion: rbac.authorization.k8s.io/v1
    metadata:
      name: vsphere-csi-node-binding
      namespace: kube-system
    subjects:
      - kind: ServiceAccount
        name: vsphere-csi-node
        namespace: kube-system
    roleRef:
      kind: Role
      name: vsphere-csi-node-role
      apiGroup: rbac.authorization.k8s.io
kind: ConfigMap
metadata:
  name: ${CLUSTER_NAME}-vsphere-csi-node-binding
  namespace: ${NAMESPACE}
---
apiVersion: v1
data:
  data: |
    apiVersion: v1
    data:
      "csi-migration": "true"
      "csi-auth-check": "true"
      "online-volume-extend": "true"
      "trigger-csi-fullsync": "false"
      "async-query-volume": "true"
      "improved-csi-idempotency": "true"
      "improved-volume-topology": "true"
      "block-volume-snapshot": "true"
      "csi-windows-support": "false"
      "use-csinode-id": "true"
      "list-volumes": "false"
      "pv-to-backingdiskobjectid-mapping": "false"
      "cnsmgr-suspend-create-volume": "true"
      "topology-preferential-datastores": "true"
      "max-pvscsi-targets-per-vm": "true"
    kind: ConfigMap
    metadata:
      name: internal-feature-states.csi.vsphere.vmware.com
      namespace: kube-system
kind: ConfigMap
metadata:
  name: ${CLUSTER_NAME}-internal-feature-states.csi.vsphere.vmware.com
  namespace: ${NAMESPACE}
---
apiVersion: v1
data:
  data: |
    apiVersion: v1
    kind: Service
    metadata:
      name: vsphere-csi-controller
      namespace: kube-system
      labels:
        app: vsphere-csi-controller
    spec:
      ports:
        - name: ctlr
          port: 2112
          targetPort: 2112
          protocol: TCP
        - name: syncer
          port: 2113
          targetPort: 2113
          protocol: TCP
      selector:
        app: vsphere-csi-controller
kind: ConfigMap
metadata:
  name: ${CLUSTER_NAME}-vsphere-csi-controller-service
  namespace: ${NAMESPACE}
---
apiVersion: v1
data:
  data: |
    kind: Deployment
    apiVersion: apps/v1
    metadata:
      name: vsphere-csi-controller
      namespace: kube-system
    spec:
      replicas: 1
      strategy:
        type: RollingUpdate
        rollingUpdate:
          maxUnavailable: 1
          maxSurge: 0
      selector:
        matchLabels:
          app: vsphere-csi-controller
      template:
        metadata:
          labels:
            app: vsphere-csi-controller
            role: vsphere-csi
        spec:
          affinity:
            podAntiAffinity:
              requiredDuringSchedulingIgnoredDuringExecution:
                - labelSelector:
                    matchExpressions:
                      - key: "app"
                        operator: In
                        values:
                          - vsphere-csi-controller
                  topologyKey: "kubernetes.io/hostname"
          serviceAccountName: vsphere-csi-controller
          nodeSelector:
            node-role.kubernetes.io/control-plane: ""
          tolerations:
            - key: node-role.kubernetes.io/master
              operator: Exists
              effect: NoSchedule
            - key: node-role.kubernetes.io/control-plane
              operator: Exists
              effect: NoSchedule
            # uncomment below toleration if you need an aggressive pod eviction in case when
            # node becomes not-ready or unreachable. Default is 300 seconds if not specified.
            #- key: node.kubernetes.io/not-ready
            #  operator: Exists
            #  effect: NoExecute
            #  tolerationSeconds: 30
            #- key: node.kubernetes.io/unreachable
            #  operator: Exists
            #  effect: NoExecute
            #  tolerationSeconds: 30
          dnsPolicy: "Default"
          containers:
            - name: csi-attacher
              image: k8s.gcr.io/sig-storage/csi-attacher:v3.5.0
              args:
                - "--v=4"
                - "--timeout=300s"
                - "--csi-address=$(ADDRESS)"
                - "--leader-election"
                - "--kube-api-qps=100"
                - "--kube-api-burst=100"
              env:
                - name: ADDRESS
                  value: /csi/csi.sock
              volumeMounts:
                - mountPath: /csi
                  name: socket-dir
            - name: csi-resizer
              image: k8s.gcr.io/sig-storage/csi-resizer:v1.5.0
              args:
                - "--v=4"
                - "--timeout=300s"
                - "--handle-volume-inuse-error=false"
                - "--csi-address=$(ADDRESS)"
                - "--kube-api-qps=100"
                - "--kube-api-burst=100"
                - "--leader-election"
              env:
                - name: ADDRESS
                  value: /csi/csi.sock
              volumeMounts:
                - mountPath: /csi
                  name: socket-dir
            - name: vsphere-csi-controller
              image: gcr.io/cloud-provider-vsphere/csi/release/driver:v2.7.0
              args:
                - "--fss-name=internal-feature-states.csi.vsphere.vmware.com"
                - "--fss-namespace=$(CSI_NAMESPACE)"
              imagePullPolicy: "Always"
              env:
                - name: CSI_ENDPOINT
                  value: unix:///csi/csi.sock
                - name: X_CSI_MODE
                  value: "controller"
                - name: X_CSI_SPEC_DISABLE_LEN_CHECK
                  value: "true"
                - name: X_CSI_SERIAL_VOL_ACCESS_TIMEOUT
                  value: 3m
                - name: VSPHERE_CSI_CONFIG
                  value: "/etc/cloud/csi-vsphere.conf"
                - name: LOGGER_LEVEL
                  value: "PRODUCTION" # Options: DEVELOPMENT, PRODUCTION
                - name: INCLUSTER_CLIENT_QPS
                  value: "100"
                - name: INCLUSTER_CLIENT_BURST
                  value: "100"
                - name: CSI_NAMESPACE
                  valueFrom:
                    fieldRef:
                      fieldPath: metadata.namespace
              volumeMounts:
                - mountPath: /etc/cloud
                  name: vsphere-config-volume
                  readOnly: true
                - mountPath: /csi
                  name: socket-dir
              ports:
                - name: healthz
                  containerPort: 9808
                  protocol: TCP
                - name: prometheus
                  containerPort: 2112
                  protocol: TCP
              livenessProbe:
                httpGet:
                  path: /healthz
                  port: healthz
                initialDelaySeconds: 10
                timeoutSeconds: 3
                periodSeconds: 5
                failureThreshold: 3
            - name: liveness-probe
              image: k8s.gcr.io/sig-storage/livenessprobe:v2.7.0
              args:
                - "--v=4"
                - "--csi-address=/csi/csi.sock"
              volumeMounts:
                - name: socket-dir
                  mountPath: /csi
            - name: vsphere-syncer
              image: gcr.io/cloud-provider-vsphere/csi/release/syncer:v2.7.0
              args:
                - "--leader-election"
                - "--fss-name=internal-feature-states.csi.vsphere.vmware.com"
                - "--fss-namespace=$(CSI_NAMESPACE)"
              imagePullPolicy: "Always"
              ports:
                - containerPort: 2113
                  name: prometheus
                  protocol: TCP
              env:
                - name: FULL_SYNC_INTERVAL_MINUTES
                  value: "30"
                - name: VSPHERE_CSI_CONFIG
                  value: "/etc/cloud/csi-vsphere.conf"
                - name: LOGGER_LEVEL
                  value: "PRODUCTION" # Options: DEVELOPMENT, PRODUCTION
                - name: INCLUSTER_CLIENT_QPS
                  value: "100"
                - name: INCLUSTER_CLIENT_BURST
                  value: "100"
                - name: GODEBUG
                  value: x509sha1=1
                - name: CSI_NAMESPACE
                  valueFrom:
                    fieldRef:
                      fieldPath: metadata.namespace
              volumeMounts:
                - mountPath: /etc/cloud
                  name: vsphere-config-volume
                  readOnly: true
            - name: csi-provisioner
              image: k8s.gcr.io/sig-storage/csi-provisioner:v3.2.1
              args:
                - "--v=4"
                - "--timeout=300s"
                - "--csi-address=$(ADDRESS)"
                - "--kube-api-qps=100"
                - "--kube-api-burst=100"
                - "--leader-election"
                - "--default-fstype=ext4"
                # needed only for topology aware setup
                #- "--feature-gates=Topology=true"
                #- "--strict-topology"
              env:
                - name: ADDRESS
                  value: /csi/csi.sock
              volumeMounts:
                - mountPath: /csi
                  name: socket-dir
            - name: csi-snapshotter
              image: k8s.gcr.io/sig-storage/csi-snapshotter:v6.0.1
              args:
                - "--v=4"
                - "--kube-api-qps=100"
                - "--kube-api-burst=100"
                - "--timeout=300s"
                - "--csi-address=$(ADDRESS)"
                - "--leader-election"
              env:
                - name: ADDRESS
                  value: /csi/csi.sock
              volumeMounts:
                - mountPath: /csi
                  name: socket-dir
          volumes:
            - name: vsphere-config-volume
              secret:
                secretName: csi-vsphere-config
            - name: socket-dir
              emptyDir: {}

kind: ConfigMap
metadata:
  name: ${CLUSTER_NAME}-vsphere-csi-controller
  namespace: ${NAMESPACE}
---
apiVersion: v1
data:
  data: |
    kind: DaemonSet
    apiVersion: apps/v1
    metadata:
      name: vsphere-csi-node
      namespace: kube-system
    spec:
      selector:
        matchLabels:
          app: vsphere-csi-node
      updateStrategy:
        type: "RollingUpdate"
        rollingUpdate:
          maxUnavailable: 1
      template:
        metadata:
          labels:
            app: vsphere-csi-node
            role: vsphere-csi
        spec:
          nodeSelector:
            kubernetes.io/os: linux
          serviceAccountName: vsphere-csi-node
          hostNetwork: true
          dnsPolicy: "ClusterFirstWithHostNet"
          containers:
            - name: node-driver-registrar
              image: k8s.gcr.io/sig-storage/csi-node-driver-registrar:v2.5.1
              args:
                - "--v=5"
                - "--csi-address=$(ADDRESS)"
                - "--kubelet-registration-path=$(DRIVER_REG_SOCK_PATH)"
              env:
                - name: ADDRESS
                  value: /csi/csi.sock
                - name: DRIVER_REG_SOCK_PATH
                  value: /var/lib/kubelet/plugins/csi.vsphere.vmware.com/csi.sock
              volumeMounts:
                - name: plugin-dir
                  mountPath: /csi
                - name: registration-dir
                  mountPath: /registration
              livenessProbe:
                exec:
                  command:
                    - /csi-node-driver-registrar
                    - --kubelet-registration-path=/var/lib/kubelet/plugins/csi.vsphere.vmware.com/csi.sock
                    - --mode=kubelet-registration-probe
                initialDelaySeconds: 3
            - name: vsphere-csi-node
              image: gcr.io/cloud-provider-vsphere/csi/release/driver:v2.7.0
              args:
                - "--fss-name=internal-feature-states.csi.vsphere.vmware.com"
                - "--fss-namespace=$(CSI_NAMESPACE)"
              imagePullPolicy: "Always"
              env:
                - name: NODE_NAME
                  valueFrom:
                    fieldRef:
                      fieldPath: spec.nodeName
                - name: CSI_ENDPOINT
                  value: unix:///csi/csi.sock
                - name: MAX_VOLUMES_PER_NODE
                  value: "59" # Maximum number of volumes that controller can publish to the node. If value is not set or zero Kubernetes decide how many volumes can be published by the controller to the node.
                - name: X_CSI_MODE
                  value: "node"
                - name: X_CSI_SPEC_REQ_VALIDATION
                  value: "false"
                - name: X_CSI_SPEC_DISABLE_LEN_CHECK
                  value: "true"
                - name: LOGGER_LEVEL
                  value: "PRODUCTION" # Options: DEVELOPMENT, PRODUCTION
                - name: GODEBUG
                  value: x509sha1=1
                - name: CSI_NAMESPACE
                  valueFrom:
                    fieldRef:
                      fieldPath: metadata.namespace
                - name: NODEGETINFO_WATCH_TIMEOUT_MINUTES
                  value: "1"
              securityContext:
                privileged: true
                capabilities:
                  add: ["SYS_ADMIN"]
                allowPrivilegeEscalation: true
              volumeMounts:
                - name: plugin-dir
                  mountPath: /csi
                - name: pods-mount-dir
                  mountPath: /var/lib/kubelet
                  # needed so that any mounts setup inside this container are
                  # propagated back to the host machine.
                  mountPropagation: "Bidirectional"
                - name: device-dir
                  mountPath: /dev
                - name: blocks-dir
                  mountPath: /sys/block
                - name: sys-devices-dir
                  mountPath: /sys/devices
              ports:
                - name: healthz
                  containerPort: 9808
                  protocol: TCP
              livenessProbe:
                httpGet:
                  path: /healthz
                  port: healthz
                initialDelaySeconds: 10
                timeoutSeconds: 5
                periodSeconds: 5
                failureThreshold: 3
            - name: liveness-probe
              image: k8s.gcr.io/sig-storage/livenessprobe:v2.7.0
              args:
                - "--v=4"
                - "--csi-address=/csi/csi.sock"
              volumeMounts:
                - name: plugin-dir
                  mountPath: /csi
          volumes:
            - name: registration-dir
              hostPath:
                path: /var/lib/kubelet/plugins_registry
                type: Directory
            - name: plugin-dir
              hostPath:
                path: /var/lib/kubelet/plugins/csi.vsphere.vmware.com
                type: DirectoryOrCreate
            - name: pods-mount-dir
              hostPath:
                path: /var/lib/kubelet
                type: Directory
            - name: device-dir
              hostPath:
                path: /dev
            - name: blocks-dir
              hostPath:
                path: /sys/block
                type: Directory
            - name: sys-devices-dir
              hostPath:
                path: /sys/devices
                type: Directory
          tolerations:
            - effect: NoExecute
              operator: Exists
            - effect: NoSchedule
              operator: Exists
kind: ConfigMap
metadata:
  name: ${CLUSTER_NAME}-vsphere-csi-node
  namespace: ${NAMESPACE}
---
apiVersion: v1
data:
  data: |
    kind: DaemonSet
    apiVersion: apps/v1
    metadata:
      name: vsphere-csi-node-windows
      namespace: kube-system
    spec:
      selector:
        matchLabels:
          app: vsphere-csi-node-windows
      updateStrategy:
        type: RollingUpdate
        rollingUpdate:
          maxUnavailable: 1
      template:
        metadata:
          labels:
            app: vsphere-csi-node-windows
            role: vsphere-csi-windows
        spec:
          nodeSelector:
            kubernetes.io/os: windows
          serviceAccountName: vsphere-csi-node
          containers:
            - name: node-driver-registrar
              image: k8s.gcr.io/sig-storage/csi-node-driver-registrar:v2.5.1
              args:
                - "--v=5"
                - "--csi-address=$(ADDRESS)"
                - "--kubelet-registration-path=$(DRIVER_REG_SOCK_PATH)"
              env:
                - name: ADDRESS
                  value: 'unix://C:\\csi\\csi.sock'
                - name: DRIVER_REG_SOCK_PATH
                  value: 'C:\\var\\lib\\kubelet\\plugins\\csi.vsphere.vmware.com\\csi.sock'
              volumeMounts:
                - name: plugin-dir
                  mountPath: /csi
                - name: registration-dir
                  mountPath: /registration
              livenessProbe:
                exec:
                  command:
                    - /csi-node-driver-registrar.exe
                    - --kubelet-registration-path=C:\\var\\lib\\kubelet\\plugins\\csi.vsphere.vmware.com\\csi.sock
                    - --mode=kubelet-registration-probe
                initialDelaySeconds: 3
            - name: vsphere-csi-node
              image: gcr.io/cloud-provider-vsphere/csi/release/driver:v2.7.0
              args:
                - "--fss-name=internal-feature-states.csi.vsphere.vmware.com"
                - "--fss-namespace=$(CSI_NAMESPACE)"
              imagePullPolicy: "Always"
              env:
                - name: NODE_NAME
                  valueFrom:
                    fieldRef:
                      apiVersion: v1
                      fieldPath: spec.nodeName
                - name: CSI_ENDPOINT
                  value: 'unix://C:\\csi\\csi.sock'
                - name: MAX_VOLUMES_PER_NODE
                  value: "59" # Maximum number of volumes that controller can publish to the node. If value is not set or zero Kubernetes decide how many volumes can be published by the controller to the node.
                - name: X_CSI_MODE
                  value: node
                - name: X_CSI_SPEC_REQ_VALIDATION
                  value: 'false'
                - name: X_CSI_SPEC_DISABLE_LEN_CHECK
                  value: "true"
                - name: LOGGER_LEVEL
                  value: "PRODUCTION" # Options: DEVELOPMENT, PRODUCTION
                - name: X_CSI_LOG_LEVEL
                  value: DEBUG
                - name: CSI_NAMESPACE
                  valueFrom:
                    fieldRef:
                      fieldPath: metadata.namespace
                - name: NODEGETINFO_WATCH_TIMEOUT_MINUTES
                  value: "1"
              volumeMounts:
                - name: plugin-dir
                  mountPath: 'C:\csi'
                - name: pods-mount-dir
                  mountPath: 'C:\var\lib\kubelet'
                - name: csi-proxy-volume-v1
                  mountPath: \\.\pipe\csi-proxy-volume-v1
                - name: csi-proxy-filesystem-v1
                  mountPath: \\.\pipe\csi-proxy-filesystem-v1
                - name: csi-proxy-disk-v1
                  mountPath: \\.\pipe\csi-proxy-disk-v1
                - name: csi-proxy-system-v1alpha1
                  mountPath: \\.\pipe\csi-proxy-system-v1alpha1
              ports:
                - name: healthz
                  containerPort: 9808
                  protocol: TCP
              livenessProbe:
                httpGet:
                  path: /healthz
                  port: healthz
                initialDelaySeconds: 10
                timeoutSeconds: 5
                periodSeconds: 5
                failureThreshold: 3
            - name: liveness-probe
              image: k8s.gcr.io/sig-storage/livenessprobe:v2.7.0
              args:
                - "--v=4"
                - "--csi-address=/csi/csi.sock"
              volumeMounts:
                - name: plugin-dir
                  mountPath: /csi
          volumes:
            - name: registration-dir
              hostPath:
                path: 'C:\var\lib\kubelet\plugins_registry\'
                type: Directory
            - name: plugin-dir
              hostPath:
                path: 'C:\var\lib\kubelet\plugins\csi.vsphere.vmware.com\'
                type: DirectoryOrCreate
            - name: pods-mount-dir
              hostPath:
                path: \var\lib\kubelet
                type: Directory
            - name: csi-proxy-disk-v1
              hostPath:
                path: \\.\pipe\csi-proxy-disk-v1
                type: ''
            - name: csi-proxy-volume-v1
              hostPath:
                path: \\.\pipe\csi-proxy-volume-v1
                type: ''
            - name: csi-proxy-filesystem-v1
              hostPath:
                path: \\.\pipe\csi-proxy-filesystem-v1
                type: ''
            - name: csi-proxy-system-v1alpha1
              hostPath:
                path: \\.\pipe\csi-proxy-system-v1alpha1
                type: ''
          tolerations:
            - effect: NoExecute
              operator: Exists
            - effect: NoSchedule
              operator: Exists
kind: ConfigMap
metadata:
  name: ${CLUSTER_NAME}-vsphere-csi-node-windows
  namespace: ${NAMESPACE}
---
apiVersion: v1
kind: Secret
metadata:
  name: ${CLUSTER_NAME}-cloud-controller-manager
  namespace: ${NAMESPACE}
stringData:
  data: |
    apiVersion: v1
    kind: ServiceAccount
    metadata: 
      labels: 
        component: cloud-controller-manager
        vsphere-cpi-infra: service-account
      name: cloud-controller-manager
      namespace: kube-system
type: addons.cluster.x-k8s.io/resource-set
---
apiVersion: v1
kind: Secret
metadata:
  name: ${CLUSTER_NAME}-cloud-provider-vsphere-credentials
  namespace: ${NAMESPACE}
stringData:
  data: |
    apiVersion: v1
    kind: Secret
    metadata: 
      labels: 
        component: cloud-controller-manager
        vsphere-cpi-infra: secret
      name: cloud-provider-vsphere-credentials
      namespace: kube-system
    stringData: 
      ${VSPHERE_SERVER}.password: ${VSPHERE_PASSWORD}
      ${VSPHERE_SERVER}.username: ${VSPHERE_USERNAME}
    type: Opaque
type: addons.cluster.x-k8s.io/resource-set
---
apiVersion: v1
data:
  data: |
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata: 
      labels: 
        component: cloud-controller-manager
        vsphere-cpi-infra: role
      name: system:cloud-controller-manager
    rules: 
    - apiGroups: 
      - ""
      resources: 
      - events
      verbs: 
      - create
      - patch
      - update
    - apiGroups: 
      - ""
      resources: 
      - nodes
      verbs: 
      - '*'
    - apiGroups: 
      - ""
      resources: 
      - nodes/status
      verbs: 
      - patch
    - apiGroups: 
      - ""
      resources: 
      - services
      verbs: 
      - list
      - patch
      - update
      - watch
    - apiGroups: 
      - ""
      resources: 
      - services/status
      verbs: 
      - patch
    - apiGroups: 
      - ""
      resources: 
      - serviceaccounts
      verbs: 
      - create
      - get
      - list
      - watch
      - update
    - apiGroups: 
      - ""
      resources: 
      - persistentvolumes
      verbs: 
      - get
      - list
      - watch
      - update
    - apiGroups: 
      - ""
      resources: 
      - endpoints
      verbs: 
      - create
      - get
      - list
      - watch
      - update
    - apiGroups: 
      - ""
      resources: 
      - secrets
      verbs: 
      - get
      - list
      - watch
    - apiGroups: 
      - coordination.k8s.io
      resources: 
      - leases
      verbs: 
      - get
      - watch
      - list
      - update
      - create
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata: 
      labels: 
        component: cloud-controller-manager
        vsphere-cpi-infra: cluster-role-binding
      name: system:cloud-controller-manager
    roleRef: 
      apiGroup: rbac.authorization.k8s.io
      kind: ClusterRole
      name: system:cloud-controller-manager
    subjects: 
    - kind: ServiceAccount
      name: cloud-controller-manager
      namespace: kube-system
    - kind: User
      name: cloud-controller-manager
    ---
    apiVersion: v1
    data: 
      vsphere.conf: |
        global: 
          port: 443
          secretName: cloud-provider-vsphere-credentials
          secretNamespace: kube-system
          thumbprint: '${VSPHERE_TLS_THUMBPRINT}'
        vcenter: 
          ${VSPHERE_SERVER}:
            datacenters: 
            - '${VSPHERE_DATACENTER}'
            server: '${VSPHERE_SERVER}'
    kind: ConfigMap
    metadata: 
      name: vsphere-cloud-config
      namespace: kube-system
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata: 
      labels: 
        component: cloud-controller-manager
        vsphere-cpi-infra: role-binding
      name: servicecatalog.k8s.io:apiserver-authentication-reader
      namespace: kube-system
    roleRef: 
      apiGroup: rbac.authorization.k8s.io
      kind: Role
      name: extension-apiserver-authentication-reader
    subjects: 
    - kind: ServiceAccount
      name: cloud-controller-manager
      namespace: kube-system
    - kind: User
      name: cloud-controller-manager
    ---
    apiVersion: apps/v1
    kind: DaemonSet
    metadata: 
      labels: 
        component: cloud-controller-manager
        tier: control-plane
      name: vsphere-cloud-controller-manager
      namespace: kube-system
    spec: 
      selector: 
        matchLabels: 
          name: vsphere-cloud-controller-manager
      template: 
        metadata: 
          labels: 
            component: cloud-controller-manager
            name: vsphere-cloud-controller-manager
            tier: control-plane
        spec: 
          affinity: 
            nodeAffinity: 
              requiredDuringSchedulingIgnoredDuringExecution: 
                nodeSelectorTerms: 
                - matchExpressions: 
                  - key: node-role.kubernetes.io/control-plane
                    operator: Exists
                - matchExpressions: 
                  - key: node-role.kubernetes.io/master
                    operator: Exists
          containers: 
          - args: 
            - --v=2
            - --cloud-provider=vsphere
            - --cloud-config=/etc/cloud/vsphere.conf
            image: gcr.io/cloud-provider-vsphere/cpi/release/manager:v1.25.3
            name: vsphere-cloud-controller-manager
            resources: 
              requests: 
                cpu: 200m
            volumeMounts: 
            - mountPath: /etc/cloud
              name: vsphere-config-volume
              readOnly: true
          hostNetwork: true
          priorityClassName: system-node-critical
          securityContext: 
            runAsUser: 1001
          serviceAccountName: cloud-controller-manager
          tolerations: 
          - effect: NoSchedule
            key: node.cloudprovider.kubernetes.io/uninitialized
            value: "true"
          - effect: NoSchedule
            key: node-role.kubernetes.io/master
            operator: Exists
          - effect: NoSchedule
            key: node-role.kubernetes.io/control-plane
            operator: Exists
          - effect: NoSchedule
            key: node.kubernetes.io/not-ready
            operator: Exists
          volumes: 
          - configMap: 
              name: vsphere-cloud-config
            name: vsphere-config-volume
      updateStrategy: 
        type: RollingUpdate
kind: ConfigMap
metadata:
  name: ${CLUSTER_NAME}-cpi-manifests
  namespace: ${NAMESPACE}




---
apiVersion: addons.cluster.x-k8s.io/v1beta1
kind: ClusterResourceSet
metadata:
  name: ${CLUSTER_NAME}-calico-module-resource
  namespace: ${NAMESPACE}
spec:
  clusterSelector:
    matchLabels:
      cluster.x-k8s.io/cluster-name: ${CLUSTER_NAME}
  resources:
    - kind: ConfigMap
      name: ${CLUSTER_NAME}-calico-module-cr
  strategy: Reconcile
---
apiVersion: v1
data:
  calico.yaml: |
    apiVersion: platform.verrazzano.io/v1alpha1
    kind: Module
    metadata:
      name: calico
      namespace: default
    spec:
      moduleName: calico
      targetNamespace: default
      values:
        tigeraOperator:
          version: ${TIGERA_TAG=v1.29.0}
        installation:
          cni:
            type: Calico
          calicoNetwork:
            bgp: Disabled
            ipPools:
              - cidr: ${POD_CIDR=192.168.0.0/16}
                encapsulation: VXLAN
          registry: ${OCNE_IMAGE_REPOSITORY=container-registry.oracle.com}
          imagePath: ${OCNE_IMAGE_PATH=olcne}
kind: ConfigMap
metadata:
  annotations:
    note: generated
  labels:
    type: generated
  name: ${CLUSTER_NAME}-calico-module-cr
  namespace: ${NAMESPACE}
```
</div>
    {{< /clipboard >}}
    </details>

1. Generate and apply the template by running the following command:
{{< clipboard >}}
<div class="highlight">

```
$ clusterctl generate yaml --from vsphere-capi.yaml | kubectl apply -f -
```
</div>
{{< /clipboard >}}

To get the `kubeconfig` file, run:
{{< clipboard >}}
<div class="highlight">

```
$ clusterctl get kubeconfig kluster1 -n kluster1 > kluster1
```
</div>
{{< /clipboard >}}

## Finish cluster configuration 

After the cluster resources are created, you must perform some additional steps to finish the configuration of the cluster.

1. If vSphere does not have a load-balancer, then you can deploy MetalLB.
{{< clipboard >}}
<div class="highlight">

```
$ export KUBECONFIG=kluster1
 
ADDRESS_RANGE=${1:-"subnet-from-vSphere-network"};
 
$ kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.7/config/manifests/metallb-native.yaml --wait=true;
$ kubectl rollout status deployment -n metallb-system controller -w;
$ kubectl apply -f -  <<EOF1
  apiVersion: metallb.io/v1beta1
  kind: IPAddressPool
  metadata:
    name: vzlocalpool
    namespace: metallb-system
  spec:
    addresses:
    - ${ADDRESS_RANGE}
EOF1
 
$ kubectl apply -f -  <<-EOF2
  apiVersion: metallb.io/v1beta1
  kind: L2Advertisement
  metadata:
    name: vzmetallb
    namespace: metallb-system
  spec:
    ipAddressPools:
    - vzlocalpool
EOF2
 
$ sleep 10;
$ kubectl wait --namespace metallb-system --for=condition=ready pod --all --timeout=300s
```
</div>
{{< /clipboard >}}

1. Create a default storage class on the cluster.
{{< clipboard >}}
<div class="highlight">

```
$ export KUBECONFIG=kluster1
$ kubectl apply -f -  <<-EOF
  kind: StorageClass
  apiVersion: storage.k8s.io/v1
  metadata:
    name: vmware-sc
    annotations:
      storageclass.kubernetes.io/is-default-class: "true"
  provisioner: csi.vsphere.vmware.com
  volumeBindingMode: WaitForFirstConsumer
EOF
```
</div>
{{< /clipboard >}}
1. Install Verrazzano on the managed cluster.
{{< clipboard >}}
<div class="highlight">

```
$ export KUBECONFIG=kluster1 

$ vz install -f - <<EOF
  apiVersion: install.verrazzano.io/v1beta1
  kind: Verrazzano
  metadata:
    name: example-verrazzano
  spec:
    profile: dev
    defaultVolumeSource:
      persistentVolumeClaim:
        claimName: verrazzano-storage
    volumeClaimSpecTemplates:
      - metadata:
          name: verrazzano-storage
        spec:
          resources:
            requests:
              storage: 2Gi
EOF
```
</div>
{{< /clipboard >}}

Your admin cluster and first managed cluster are now up and running and ready to deploy applications. You can also add more managed clusters. 

For more information, refer to the documentation for Cluster API and Cluster API vSphere

* [Kubernetes Cluster API Documentation](https://cluster-api.sigs.k8s.io/introduction.html)
* [Kubernetes Cluster API Provider vSphere](https://github.com/kubernetes-sigs/cluster-api-provider-vsphere)

## Troubleshoot the deployment

If the deployment of the vSphere resources fails, then you can check the log files to diagnose the issue.

The vSphere cluster controller provider logs:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl logs -n verrazzano-capi -l cluster.x-k8s.io/provider=infrastructure-vsphere
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

**NOTE**: If the CSI pod deploys before Calico, then the pod may enter a `CrashLoop` state. Restart the pod to fix the issue.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl --kubeconfig kluster1 scale deploy  -n kube-system vsphere-csi-controller --replicas=0
$ kubectl --kubeconfig kluster1 scale deploy  -n kube-system vsphere-csi-controller --replicas=1
```
</div>
{{< /clipboard >}}

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