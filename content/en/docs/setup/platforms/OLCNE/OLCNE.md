---
title: Oracle Cloud Native Environment
description: Instructions for setting up an Oracle Cloud Native Environment cluster for Verrazzano
linkTitle: Oracle Cloud Native Environment
weight: 7
draft: false
---

## Prepare for the Oracle Cloud Native Environment installation
[Oracle Cloud Native Environment](https://docs.oracle.com/en/operating-systems/olcne/) can be installed in several different types of environments.
These range from physical, on-premises hardware to virtualized cloud infrastructure.
The Oracle Cloud Native Environment installation instructions assume that networking and compute resources already exist.
The basic infrastructure requirements are a network with a public and private subnet
and a set of hosts connected to those networks.

### Oracle Cloud Infrastructure example
The following is an example of Oracle Cloud Infrastructure that can be used to evaluate Verrazzano installed on Oracle Cloud Native Environment.
If other environments are used, the capacity and configuration should be similar.

You can use the VCN Wizard of the Oracle Cloud Infrastructure Console to automatically create most of the described network infrastructure.
Additional security lists/rules, as detailed in the following sections, need to be added manually.
All Classless Inter-Domain Routing (CIDR) values provided are examples and can be customized as required.

### Virtual Cloud Network (for example, CIDR 10.0.0.0/16)
**Public Subnet (for example, CIDR 10.0.0.0/24)**

Security List / Ingress Rules

| Stateless | Destination | Protocol | Source Ports | Destination Ports | Type & Code | Description |
|-----------|-------------|----------|--------------|-------------------|-------------|-------------|
| No       | `0.0.0.0/0`  | ICMP    |               |                   | 3, 4      | ICMP errors        |
| No       | `10.0.0.0/16`| ICMP    |               |                   | 3         | ICMP errors        |
| No       | `0.0.0.0/0`  | TCP     | All           | 22                |           | SSH                |
| No       | `0.0.0.0/0`  | TCP     | All           | 443               |           | HTTPS load balancer |


Security List / Egress Rules

|Stateless|Destination|Protocol|Source Ports| Destination Ports |Type & Code|Description        |
|---------|-----------|--------|------------|-------------------|-----------|-------------------|
|No       |`10.0.1.0/24`|TCP     |All         | 22                |           |SSH                |
|No       |`10.0.1.0/24`|TCP     |All         | 31443             |           |HTTPS load balancer|
|No       |`10.0.1.0/24`|TCP     |All         | 32443             |           |HTTPS load balancer|

**Private Subnet (for example, CIDR 10.0.1.0/24)**

Security List / Ingress Rules

|Stateless| Destination   | Protocol | Source Ports | Destination Ports | Type & Code |Description          |
|---------|---------------|----------|--------------|-------------------|------------|---------------------|
|No       | `0.0.0.0/0`   | ICMP     |              |                   | 3, 4       |ICMP errors          |
|No       | `10.0.0.0/16` | ICMP     |              |                   | 3          |ICMP errors          |
|No       | `10.0.0.0/16` | TCP      | All          | 22                |            |SSH                  |
|No       | `10.0.0.0/24` | TCP      | All          | 31443             |            |HTTPS load balancer  |
|No       | `10.0.0.0/24` | TCP      | All          | 32443             |            |HTTPS load balancer  |
|No       | `10.0.1.0/24` | UDP      | All          | 111               |            |NFS                  |
|No       | `10.0.1.0/24` | TCP      | All          | 111               |            |NFS                  |
|No       | `10.0.1.0/24` | UDP      | All          | 2048              |            |NFS                  |
|No       | `10.0.1.0/24` | TCP      | All          | 2048-2050         |            |NFS                  |
|No       | `10.0.1.0/24` | TCP      | All          | 2379-2380         |            |Kubernetes etcd      |
|No       | `10.0.1.0/24` | TCP      | All          | 6443              |            |Kubernetes API Server|
|No       | `10.0.1.0/24` | TCP      | All          | 6446              |            |MySQL                |
|No       | `10.0.1.0/24` | TCP      | All          | 8090-8091         |            |Oracle Cloud Native Environment Platform Agent |
|No       | `10.0.1.0/24` | UDP      | All          | 8472              |            |Flannel              |
|No       | `10.0.1.0/24` | TCP      | All          | 10250-10255       |            |Kubernetes Kublet    |

Security List / Egress Rules

|Stateless| Destination   |Protocol|Source Ports|Destination Ports|Type and Code|Description       |
|---------|---------------|--------|------------|-----------------|-------------|------------------|
|No       | `10.0.0.0/16` |TCP     |            |                 |             |All egress traffic|

**DHCP Options**

|DNS Type                 |
|-------------------------|
|Internet and VCN Resolver|

**Route Tables**

Public Subnet Route Table Rules

|Destination|Target          |
|-----------|----------------|
|`0.0.0.0/0`  |Internet Gateway|

Private Subnet Route Table Rules

| Destination     | Target         |
|----------------|---------------|
| `0.0.0.0/0`     | NAT Gateway    |
| All Oracle Cloud Infrastructure Services| Service Gateway|

**Internet Gateway**

**NAT Gateway**

**Service Gateway**

The following compute resources adhere to the guidelines provided in [Oracle Cloud Native Environment: Getting Started](https://docs.oracle.com/en/operating-systems/olcne/).
The attributes indicated (for example, Subnet, RAM, Shape, and Image) are recommendations that have been tested.
Other values can be used if required.

**Compute Instances**

| Role                          | Subnet  | Suggested RAM | Compatible VM Shape | Compatible VM Image |
|-------------------------------|---------|---------------|---------------------|---------------------|
| SSH Jump Host                 | Public  | 8GB           | VM.Standard3.Flex    | Oracle Linux 7.9    |
| Oracle Cloud Native Environment Operator Host           | Private | 16GB          | VM.Standard3.Flex    | Oracle Linux 7.9    |
| Kubernetes Control Plane Node | Private | 32GB          | VM.Standard3.Flex    | Oracle Linux 7.9    |
| Kubernetes Worker Node 1      | Private | 32GB          | VM.Standard3.Flex    | Oracle Linux 7.9    |
| Kubernetes Worker Node 2      | Private | 32GB          | VM.Standard3.Flex    | Oracle Linux 7.9    |
| Kubernetes Worker Node 3      | Private | 32GB          | VM.Standard3.Flex    | Oracle Linux 7.9    |

## Install Oracle Cloud Native Environment
Deploy Oracle Cloud Native Environment with the Kubernetes module, following instructions from [Oracle Cloud Native Environment: Getting Started](https://docs.oracle.com/en/operating-systems/olcne/).
* Use a single Kubernetes control plane node.
* Skip the Kubernetes API load balancer ([load balancer](https://docs.oracle.com/en/operating-systems/olcne/1.5/start/install.html#install-lb)).
* Use private CA certificates ([private certs](https://docs.oracle.com/en/operating-systems/olcne/1.5/start/install.html#certs-private)).

## Prepare for the Verrazzano installation

A Verrazzano Oracle Cloud Native Environment deployment requires:
* A default storage provider that supports "Multiple Read/Write" mounts. For example, an NFS service like:
    * Oracle Cloud Infrastructure File Storage Service.
    * A hardware-based storage system that provides NFS capabilities.
* Load balancers in front of the worker nodes in the cluster.
* DNS records that reference the load balancers.

Examples for meeting these requirements follow.

### Storage
Verrazzano requires persistent storage for several components.
This persistent storage is provided by a default storage class.
A number of persistent storage providers exist for Kubernetes.
This guide will focus on pre-allocated persistent volumes.
In particular, the provided samples will illustrate the use of Oracle Cloud Infrastructure's File System.

#### Oracle Cloud Infrastructure example  
Before storage can be exposed to Kubernetes, you must create it.
In Oracle Cloud Infrastructure, you do this using File System resources.
Using the Oracle Cloud Infrastructure Console, create a new File System.
Within the new File System, create an Export.
Remember the `Export Path` value because you will use it later.
Also note the Mount Target's `IP Address`.

After the exports have been created, you will need to create referenced persistent volume folders (for example, `/example/pv0001`).
In Oracle Cloud Infrastructure, you can do this by mounting the export on one of the Kubernetes worker nodes and creating the folders.
In the following example, the value `/example` is the `Export Path` and `10.0.1.8` is the Mount Target's `IP Address`.
Run the following command on one of the Kubernetes worker nodes.
This will result in the creation of nine persistent volume folders.

```
$ sudo mount 10.0.1.8:/example /mnt
$ for x in {0001..0009}; do sudo mkdir -p /mnt/pv${x} && sudo chmod 777 /mnt/pv${x}; done
```

#### Persistent volumes
A default Kubernetes storage class is required by Verrazzano.
When using pre-allocated PersistentVolumes, for example NFS, persistent volumes should be declared as following.
The value for `name` may be customized but will need to match the PersistentVolume `storageClassName` value later.
* Create a default StorageClass
  ```
  $ cat << EOF | kubectl apply -f -
    apiVersion: storage.k8s.io/v1
    kind: StorageClass
    metadata:
      name: example-nfs
      annotations:
        storageclass.kubernetes.io/is-default-class: "true"
    provisioner: kubernetes.io/no-provisioner
    volumeBindingMode: WaitForFirstConsumer
  EOF
  ```
* Create the required number of PersistentVolume resources.
  The Verrazzano system requires five persistent volumes for itself.
  The following command creates nine persistent volumes.
  The value for `storageClassName` must match the previously defined `StorageClass` name.
  The values for `name` may be customized.
  The value for `path` must match the `Export Path` of the Export mentioned earlier, combined with the persistent volume folder from before.
  Change the value for `server` to match the location of your file system server.  
  ```
  $ for n in {0001..0009}; do cat << EOF | kubectl apply -f -
    apiVersion: v1
    kind: PersistentVolume
    metadata:
      name: pv${n}
    spec:
      storageClassName: example-nfs
      accessModes:
        - ReadWriteOnce
        - ReadWriteMany
      capacity:
        storage: 50Gi
      nfs:
        path: /example/pv${n}
        server: 10.0.1.8
      volumeMode: Filesystem
      persistentVolumeReclaimPolicy: Recycle
  EOF
  done
  ```

#### Configuring custom recycler Pod template

When a Verrazzano installation is [deleted]({{< relref "/docs/setup/uninstall/uninstall.md" >}}), the `PersistentVolumes` created in the preceding section are recycled by Kubernetes. As explained [here](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#recycle), Kubernetes platforms like Oracle Cloud Native Environment can have a custom recycler Pod defined. This Pod could require access to images which may not be available to the environment. For example, in the case of [local registry setup]({{< relref "/docs/setup/private-registry/private-registry.md" >}}) without access to the public Internet, the Pod previously defined will fail to start because it will not be able to pull the public `k8s.gcr.io/busybox` image. In such cases, it is required to have the specified container image locally on the Kubernetes node or in the local registry and use the argument `--pv-recycler-pod-template-filepath-nfs` to specify a custom Pod template for the recycler.

For example, to configure the recycler Pod template on an Oracle Cloud Native Environment based Verrazzano cluster:
1. Configure the recycler Pod template as a `ConfigMap` entry.
    ```
    apiVersion: v1
    kind: ConfigMap
    metadata:
    name: recycler-pod-config
    namespace: kube-system
    data:
    recycler-pod.yaml: |
        apiVersion: v1
        kind: Pod
        metadata:
        name: pv-recycler
        namespace: default
        spec:
        restartPolicy: Never
        volumes:
        - name: vol
            hostPath:
            path: /any/path/it/will/be/replaced
        containers:
        - name: pv-recycler
            # busybox image from local registry
            image: "local-registry/busybox"
            command: ["/bin/sh", "-c", "test -e /scrub && rm -rf /scrub/..?* /scrub/.[!.]* /scrub/*  && test -z \"$(ls -A /scrub)\" || exit 1"]
            volumeMounts:
            - name: vol
            mountPath: /scrub
    ```
2. Edit the `kube-controller-manager` Pod in the `kube-system` namespace.
    ```
    $ kubectl edit pod kube-controller-manager-xxxxx -n kube-system
    ```
   Alternatively, you can edit the manifest file at `/etc/kubernetes/manifests/kube-controller-manager.yaml` on the control-plane node.
3. Add the ConfigMap `recycler-pod-config` as a `volume` to the Pod spec.
4. Add the ConfigMap entry `recycler-pod.yaml` as a `volumeMount` to the Pod spec.
5. Add the `--pv-recycler-pod-template-filepath-nfs` argument to the `command`, with value as `mountPath` of `recycler-pod.yaml` in the Pod.
    ```
    apiVersion: v1
    kind: Pod
    ...
    spec:
    containers:
    - command:
        - kube-controller-manager
        - --allocate-node-cidrs=true
        ...
        - --pv-recycler-pod-template-filepath-nfs=/etc/recycler-pod.yaml
        ...
        volumeMounts:
        ...
        - name: recycler-config-volume
        mountPath: /etc/recycler-pod.yaml
        subPath: recycler-pod.yaml   
    ...
    volumes:
    ...
    - name: recycler-config-volume
        configMap:
            name: recycler-pod-config
    ```

### Load balancers
Verrazzano on Oracle Cloud Native Environment uses external load balancer services.
These will not automatically be provided by Verrazzano or Kubernetes.
Two load balancers must be deployed outside of the subnet used for the Kubernetes cluster.
One load balancer is for management traffic and the other for application traffic.

Specific steps will differ for each load balancer provider. 
Instructions for the Oracle Cloud Infrastructure example:
1. Create a load balancer; and it should be in the same VCN as the Kubernetes cluster nodes.
2. For the listener and backend set ports, refer to [External Load Balancers]({{< relref "/docs/setup/customizing/externalLBs.md" >}}).


### DNS
Both wildcard DNS and external DNS are supported in Oracle Cloud Native Environment. If using wildcard DNS, skip this section and go to [Next steps](#next steps)

When using the Verrazzano`spec.components.dns.external` DNS type, the installer searches the DNS zone you provide for two specific A records.
These are used to configure the cluster and should refer to external addresses of the load balancers in the previous step.
The A records will need to be created manually.

|Record             | Use                                                                                              |
|-------------------|--------------------------------------------------------------------------------------------------|
|`ingress-mgmt`       | Set as the `.spec.externalIPs` value of the `ingress-controller-nginx-ingress-controller` service. |
|`ingress-verrazzano` | Set as the `.spec.externalIPs` value of the `istio-ingressgateway` service.                       |

For example:
```
11.22.33.44                                   A       ingress-mgmt.myenv.example.com.
11.22.33.55                                    A       ingress-verrazzano.myenv.example.com.
```

When using externalDNS, the following DNS CNAME records need to be added and should point to the `ingress-mgmt` address.
```
verrazzano.myenv.example.com                    CNAME   ingress-mgmt.myenv.example.com.
keycloak.myenv.example.com                      CNAME   ingress-mgmt.myenv.example.com.
rancher.myenv.example.com                       CNAME   ingress-mgmt.myenv.example.com.

grafana.vmi.system.myenv.example.com            CNAME   ingress-mgmt.myenv.example.com.
prometheus.vmi.system.myenv.example.com         CNAME   ingress-mgmt.myenv.example.com.
kiali.vmi.system.myenv.example.com              CNAME   ingress-mgmt.myenv.example.com.
kibana.vmi.system.myenv.example.com             CNAME   ingress-mgmt.myenv.example.com.
elasticsearch.vmi.system.myenv.example.com      CNAME   ingress-mgmt.myenv.example.com.
```
For accessing applications, the following CNAME records need to be added.
```
*.myenv.example.com                             CNAME   ingress-verrazzano.myenv.example.com.
```
#### Oracle Cloud Infrastructure example
DNS is configured in Oracle Cloud Infrastructure by creating DNS zones in the Oracle Cloud Infrastructure Console.
When creating a DNS zone, use these values:
* Method: Manual
* Zone Name: `<dns-suffix>`
* Zone Type: Primary

The value for `<dns-suffix>` excludes the environment (for example, use the `example.com` portion of `myenv.example.com`).

DNS A records must be manually added to the zone and published using values described previously.
DNS CNAME records also must be addedd manually, in the same way.

During the Verrazzano installation, these steps should be performed on the Oracle Cloud Native Environment operator node.

Edit the sample Verrazzano custom resource [install-olcne.yaml]( {{< release_source_url path=platform-operator/config/samples/install-olcne.yaml >}} ) file and provide these configuration settings for your Oracle Cloud Native Environment:

- The value for `spec.environmentName` is a unique DNS subdomain for the cluster (for example, `myenv` in `myenv.example.com`).
- The value for `spec.components.dns.external.suffix` is the remainder of the DNS domain (for example, `example.com` in `myenv.example.com`).
- Under `spec.components.ingress.nginxInstallArgs`, the value for `controller.service.externalIPs` is the IP address of `ingress-mgmt.<myenv>.<example.com>` configured during DNS set up.
- Under  `spec.components.istio.istioInstallArgs`, the value for `gateways.istio-ingressgateway.externalIPs` is the IP address of `ingress-verrazzano.<myenv>.<example.com>` configured during DNS setup.

You will install Verrazzano using the `external` DNS type (the example custom resource for Oracle Cloud Native Environment is already configured to use `spec.components.dns.external`).

Set the following environment variable:

The value for `<path to valid Kubernetes config>` is typically `${HOME}/.kube/config`.
```
$ export KUBECONFIG=$VERRAZZANO_KUBECONFIG
```

##### Configure Istio Gateway resource for non-SNI requests

When a cloud load balancer is set up as an application load balancer in Verrazzano, it is possible that [SNI](https://www.cloudflare.com/en-in/learning/ssl/what-is-sni/) is not forwarded from the load balancer to the `istio-ingressgateway` as described [here](https://istio.io/latest/docs/ops/common-problems/network-issues/?_ga=2.71843408.277402657.1650537788-2065972972.1650537788#configuring-sni-routing-when-not-sending-sni). This may result in traffic not getting routed to the application service. To make it work, you need to edit the `Gateway` resource and add `*` to the `hosts` list.
```
apiVersion: networking.istio.io/v1beta1
kind: Gateway
...
spec:
  selector:
    istio: ingressgateway
  servers:
  - hosts:
    - '*'
    - ...
```

## Next steps

To continue, see the [Installation Guide]({{< relref "/docs/setup/install/installation.md#install-the-verrazzano-platform-operator" >}}).
