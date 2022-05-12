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
Additional security lists/rules, as detailed below, need to be added manually.
All CIDR values provided are examples and can be customized as required.

### Virtual Cloud Network (for example, CIDR 10.0.0.0/16)
**Public Subnet (for example, CIDR 10.0.0.0/24)**

Security List / Ingress Rules

| Stateless | Destination | Protocol | Source Ports | Destination Ports | Type & Code | Description |
|-----------|-------------|----------|--------------|-------------------|-------------|-------------|
| No       | `0.0.0.0/0`  | ICMP    |               |                   | 3, 4      | ICMP errors        |
| No       | `10.0.0.0/16`| ICMP    |               |                   | 3         | ICMP errors        |
| No       | `0.0.0.0/0`  | TCP     | All           | 22                |           | SSH                |
| No       | `0.0.0.0/0`  | TCP     | All           | 80                |           | HTTP load balancer |
| No       | `0.0.0.0/0`  | TCP     | All           | 443               |           | HTTPS load balancer |


Security List / Egress Rules

|Stateless|Destination|Protocol|Source Ports|Destination Ports|Type & Code|Description        |
|---------|-----------|--------|------------|-----------------|-----------|-------------------|
|No       |`10.0.1.0/24`|TCP     |All         |22               |           |SSH                |
|No       |`10.0.1.0/24`|TCP     |All         |30080            |           |HTTP load balancer |
|No       |`10.0.1.0/24`|TCP     |All         |30443            |           |HTTPS load balancer|
|No       |`10.0.1.0/24`|TCP     |All         |31380            |           |HTTP load balancer |
|No       |`10.0.1.0/24`|TCP     |All         |31390            |           |HTTPS load balancer|

**Private Subnet (for example, CIDR 10.0.1.0/24)**

Security List / Ingress Rules

|Stateless|Destination|Protocol|Source Ports|Destination Ports|Type & Code|Description          |
|---------|-----------|--------|------------|-----------------|-----------|---------------------|
|No       |`0.0.0.0/0`  |ICMP    |            |                 |3, 4       |ICMP errors          |
|No       |`10.0.0.0/16`|ICMP    |            |                 |3          |ICMP errors          |
|No       |`10.0.0.0/16`|TCP     |All         |22               |           |SSH                  |
|No       |`10.0.0.0/24`|TCP     |All         |30080            |           |HTTP load balancer   |
|No       |`10.0.0.0/24`|TCP     |All         |30443            |           |HTTPS load balancer  |
|No       |`10.0.0.0/24`|TCP     |All         |31380            |           |HTTP load balancer   |
|No       |`10.0.0.0/24`|TCP     |All         |31390            |           |HTTPS load balancer  |
|No       |`10.0.1.0/24`UDP      |All         |111              |           |NFS                  |
|No       |`10.0.1.0/24`|TCP     |All         |111              |           |NFS                  |
|No       |`10.0.1.0/24`|UDP     |All         |2048             |           |NFS                  |
|No       |`10.0.1.0/24`|TCP     |All         |2048-2050        |           |NFS                  |
|No       |`10.0.1.0/24`|TCP     |All         |2379-2380        |           |Kubernetes etcd      |
|No       |`10.0.1.0/24`|TCP     |All         |6443             |           |Kubernetes API Server|
|No       |`10.0.1.0/24`|TCP     |All         |6446             |           |MySQL                |
|No       |`10.0.1.0/24`|TCP     |All         |8090-8091        |           |Oracle Cloud Native Environment Platform Agent |
|No       |`10.0.1.0/24`|UDP     |All         |8472             |           |Flannel              |
|No       |`10.0.1.0/24`|TCP     |All         |10250-10255      |           |Kubernetes Kublet    |

Security List / Egress Rules

|Stateless|Destination|Protocol|Source Ports|Destination Ports|Type and Code|Description       |
|---------|-----------|--------|------------|-----------------|-------------|------------------|
|No       |`10.0.0.0/0` |TCP     |            |                 |             |All egress traffic|

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
| SSH Jump Host                 | Public  | 8GB           | VM.Standard.E2.1    | Oracle Linux 7.8    |
| Oracle Cloud Native Environment Operator Host           | Private | 16GB          | VM.Standard.E2.2    | Oracle Linux 7.8    |
| Kubernetes Control Plane Node | Private | 32GB          | VM.Standard.E2.4    | Oracle Linux 7.8    |
| Kubernetes Worker Node 1      | Private | 32GB          | VM.Standard.E2.4    | Oracle Linux 7.8    |
| Kubernetes Worker Node 2      | Private | 32GB          | VM.Standard.E2.4    | Oracle Linux 7.8    |
| Kubernetes Worker Node 3      | Private | 32GB          | VM.Standard.E2.4    | Oracle Linux 7.8    |

## Install Oracle Cloud Native Environment
Deploy Oracle Cloud Native Environment with the Kubernetes module, following instructions from [Oracle Cloud Native Environment: Getting Started](https://docs.oracle.com/en/operating-systems/olcne/).
* Use a single Kubernetes control plane node.
* Skip the Kubernetes API load balancer ([3.4.3](https://docs.oracle.com/en/operating-systems/olcne/1.1/start/install-lb.html)).
* Use private CA certificates ([3.5.3](https://docs.oracle.com/en/operating-systems/olcne/1.1/start/certs-private.html)).

## Prepare for the Verrazzano installation

A Verrazzano Oracle Cloud Native Environment deployment requires:
* A default storage provider that supports "Multiple Read/Write" mounts. For example, an NFS service like:
    * Oracle Cloud Infrastructure File Storage Service.
    * A hardware-based storage system that provides NFS capabilities.
* Load balancers in front of the worker nodes in the cluster.
* DNS records that reference the load balancers.

**NOTE**: The target ports for the load balancer backends cannot be determined until you install Verrazzano.  
You can create the load balancers before you install, but post-installation configuration is required.

Examples for meeting these requirements follow.

### Storage
Verrazzano requires persistent storage for several components.
This persistent storage is provided by a default storage class.
A number of persistent storage providers exist for Kubernetes.
This guide will focus on pre-allocated persistent volumes.
In particular, the provided samples will illustrate the use of Oracle Cloud Infrastructure's File System.

#### Oracle Cloud Infrastructure example  
Before storage can be exposed to Kubernetes, it must be created.
In Oracle Cloud Infrastructure, this is done using File System resources.
Using the Oracle Cloud Infrastructure Console, create a new File System.
Within the new File System, create an Export.
Remember the value used for  `Export Path` as it will be used later.
Also note the Mount Target's `IP Address` for use later.

After the exports have been created, referenced persistent volume folders (for example, `/example/pv0001`) will need to be created.
In Oracle Cloud Infrastructure, this can be done by mounting the export on one of the Kubernetes worker nodes and creating the folders.
In the following example, the value `/example` is the `Export Path` and `10.0.1.8` is the Mount Target's `IP Address`.
The following command should be run on one of the Kubernetes worker nodes.
This will result in the creation of nine persistent volume folders.
The reason for nine persistent volume folders is covered in the next section.
```
$ sudo mount 10.0.1.8:/example /mnt
$ for x in {0001..0009}; do sudo mkdir -p /mnt/pv${x} && sudo chmod 777 /mnt/pv${x}; done
```

#### Persistent Volumes
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
  The value for `storageClassName` must match the above `StorageClass` name.
  The values for `name` may be customized.
  The value for `path` must match the `Export Path` of the Export from above, combined with the persistent volume folder from above.
  The value for `server` must be changed to match the location of your file system server.  
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
   Alternatively, you can also edit the manifest at `/etc/kubernetes/manifests/kube-controller-manager.yaml` on control-plane node.
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

Specific steps will differ for each load balancer provider, but a generic configuration and an Oracle Cloud Infrastructure example follow.

#### Generic configuration:

* Target Host: Host names of Kubernetes worker nodes
* Target Ports: See table
* External Ports: See table
* Distribution: Round-robin
* Health Check: TCP

##### Backend for management load balancer
You must install Verrazzano to get the target ports for each load balancer backend.
In the following table, those ports are marked TBD. Run the following command to get the target
ports for the NGINX Ingress Controller:
```
$ kubectl get service ingress-controller-ingress-nginx-controller -n ingress-nginx
```
In the `PORT(S)` column you will see the target port associated with port 80 and 443, for example: `80:30080/TCP,443:30443`.  
Use these target port values for the NGINX Ingress Controller load balancer backend.

| Service Name                                  | Type  |  External Port          | Target Port |
|---------------------------------------------|-------|-------------------------|-------------|
`ingress-controller-nginx-ingress-controller` | TCP   | 80                      | TBD         |  
`ingress-controller-nginx-ingress-controller` | TCP   | 443                     | TBD         |  

##### Backend for application load balancer
Get the target ports for the Istio ingress gateway service using the following command:
```
$ kubectl get service  istio-ingressgateway  -n  istio-system
```
Use these port values for the Istio ingress gateway load balancer backend.

| Service Name                                  | Type  |  External Port          | Target Port |
|-----------------------------------------------|-------|-------------------------|-------------|
| `istio-ingressgateway`                        | TCP   | 80                      | TBD         |
| `istio-ingressgateway`                        | TCP   | 443                     | TBD         |


#### Oracle Cloud Infrastructure example
You can use the following details to create Oracle Cloud Infrastructure load balancers for accessing application and management user interfaces, respectively.
These load balancers will route HTTP/HTTPS traffic from the Internet to the private subnet.
If load balancers are desired, then they should be created now even though the application and management endpoints will be installed later.

**NOTE**: In the following list, the using port 0 for the health check indicates that the backend ports should be used.

* Application Load Balancer: Public Subnet
  * Listeners
    * HTTP Listener: Protocol TCP, Port 80
    * HTTPS Listener: Protocol TCP, Port 443
  * Backend Sets
    * HTTP Backend Sets:
      * Health Check: Protocol TCP, Port 0
      * Backends: Kubernetes Worker Nodes, Port TBD, Distribution Policy Weighted Round Robin
    * HTTPS Backend Sets
      * Health Check: Protocol TCP, Port 0
      * Backends: Kubernetes Worker Nodes, Port TBD, Distribution Policy Weighted Round Robin
* Management Load Balancer: Public Subnet
  * Listeners
    * HTTP Listener: Protocol TCP, Port 80
    * HTTPS Listener: Protocol TCP, Port 443
  * Backend Sets
    * HTTP Backend Sets:
      * Health Check: Protocol TCP, Port 0
      * Backends: Kubernetes Worker Nodes, Port TBD, Distribution Policy Weighted Round Robin
    * HTTPS Backend Sets
      * Health Check: Protocol TCP, Port 0
      * Backends: Kubernetes Worker Nodes, Port TBD, Distribution Policy Weighted Round Robin

#### Configuring self-signed certificate for the load balancer
To configure an HTTPS listener or an HTTPS backend, you must configure an SSL certificate as described in [SSL Certificate for Load Balancers](https://docs.oracle.com/en-us/iaas/Content/Balance/Tasks/managingcertificates.htm).

When the SSL certificate being configured as the Load Balancer Managed Certificate is a self-signed certificate, then the certificate should also be added as the CA certificate on the <i>Add Certificate</i> page in the Oracle Cloud Infrastructure Console.
![](/docs/images/olcne-lb-self-signed-cert.png)

### DNS
When using the Verrazzano`spec.components.dns.external` DNS type, the installer searches the DNS zone you provide for two specific A records.
These are used to configure the cluster and should refer to external addresses of the load balancers in the previous step.
The A records will need to be created manually.

**NOTE**: At this time, the only supported deployment for Oracle Cloud Native Environment is the external DNS type.

|Record             | Use                                                                                              |
|-------------------|--------------------------------------------------------------------------------------------------|
|`ingress-mgmt`       | Set as the `.spec.externalIPs` value of the `ingress-controller-nginx-ingress-controller` service. |
|`ingress-verrazzano` | Set as the `.spec.externalIPs` value of the `istio-ingressgateway` service.                       |

For example:
```
198.51.100.10                                   A       ingress-mgmt.myenv.example.com.
203.0.113.10                                    A       ingress-verrazzano.myenv.example.com.
```

Verrazzano installation will result in a number of management services that need to point to the `ingress-mgmt` address.
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

For simplicity, an administrator may want to create [wildcard DNS records](https://tools.ietf.org/html/rfc1034#section-4.3.3) for the management addresses:
```
*.system.myenv.example.com                      CNAME   ingress-mgmt.myenv.example.com.
```
OR
```
*.myenv.example.com                             CNAME   ingress-mgmt.myenv.example.com.
```
#### Oracle Cloud Infrastructure example
DNS is configured in Oracle Cloud Infrastructure by creating DNS zones in the Oracle Cloud Infrastructure Console.
When creating a DNS zone, use these values:
* Method: Manual
* Zone Name: `<dns-suffix>`
* Zone Type: Primary

The value for `<dns-suffix>` excludes the environment (for example, use the `example.com` portion of `myenv.example.com`).

DNS A records must be manually added to the zone and published using values described above.
DNS CNAME records, in the same way.



During the Verrazzano install, these steps should be performed on the Oracle Cloud Native Environment operator node.

Edit the sample Verrazzano custom resource [install-olcne.yaml]( {{< release_source_url path=platform-operator/config/samples/install-olcne.yaml >}} ) file and provide these configuration settings for your Oracle Cloud Native Environment:

- The value for `spec.environmentName` is a unique DNS subdomain for the cluster (for example, `myenv` in `myenv.example.com`).
- The value for `spec.components.dns.external.suffix` is the remainder of the DNS domain (for example, `example.com` in `myenv.example.com`).
- Under `spec.components.ingress.nginxInstallArgs`, the value for `controller.service.externalIPs` is the IP address of `ingress-mgmt.<myenv>.<example.com>` configured during DNS set up.
- Under  `spec.components.istio.istioInstallArgs`, the value for `gateways.istio-ingressgateway.externalIPs` is the IP address of `ingress-verrazzano.<myenv>.<example.com>` configured during DNS set up.

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
