---
title: "Before you begin"
weight: 1
---

# Before you begin

Before you install the Verrazzano Enterprise Container Platform, you need to plan your
topology and understand which components you'll need to install in each Kubernetes
cluster and what additional infrastructure components and services are required.

## Plan your topology

There are a number of topology decisions to make before beginning installation:

* How many Kubernetes clusters to include in the environment.
* How the clusters will be connected to each other.
* Which cluster will run the infrastructure components.
* Which cluster(s) will run application workloads.
* more

### Management cluster

You must have one Kubernetes cluster that is designated as the "Verrazzano Management
Cluster."  This is the cluster where all Verrazzano system and infrastructure
components will be installed.  

### Managed clusters

You can have one or more Kubernetes clusters that are designated as the "Verrazzano
Managed Clusters."  These clusters will be used to run application workload.

In non-production environments only, the Verrazzano Management Cluster can also be
designated as managed clusters.  This allows you to run a non-production Verrazzano
environment in a single Kubernetes cluster.



## Prerequisites

The following prerequisites must be met to install the Verrazzano Enterprise Container Platform:

* One or more Kubernetes clusters in which to run Verrazzano.  
    * Supported versions are 1.15, 1.16, 1.17 and 1.18.
    * All clusters must be running the same version of Kubernetes.
    * Supported distributions and managed services are:
        * Oracle Linux Cloud Native Environment 1.1 with Kubernetes 1.17.4.
        * Oracle Cloud Infrastructure Container Engine for Kubernetes (commonly known as "OKE")
          with Kubernetes 1.15.7.
        * Azure Kubernetes Service (any available version 1.15 or later, unless designated "preview").
        * Amazon Elastic Kubernetes Service with Kubernetes 1.15.
        * Rancher Kubernetes Engine 0.2.10 with Kubernetes 1.15.11.
        * Kind (Kubernetes in Docker) is supported for non-production environments only.
    * At least one cluster (the "management cluster") should have at least 120GB of RAM
      across the worker nodes.
* If the clusters are in different data centers, we recommend that you have a private network
  between the clusters, for example an IPSec Virtual Private Network, or a hardware-based
  solution like Oracle Cloud Infrastructure FastConnect.  You must be able to route IP traffic
  from each worker in each cluster to either each worker in every other cluster, or alternatively
  to a load balancer which provides access to workers in each other cluster.
* A DNS provider where you can create DNS `A` and `CNAME` records. This could
  be a "magic DNS" service like [xip.io](http://xip.io) for a non-production environment.
* A load balancer in front of the worker nodes in each cluster.  For a non-production environment,
  you may choose to access your clusters using NodePorts instead, in which case the load balancer
  is not required.
* A certificate provider (or certificate authority) from whom you can obtain signed X.509 certificates,
  for example Let's Encrypt.
* A storage provider that supports "Read/Write Multiple" mounts.  For example, an NFS service like:
    * Oracle Cloud Infrastructure File Storage Service.
    * Azure Files.
    * Amazon Elastic File System.
    * A hardware-based storage system that provides NFS capabilities.

### Prerequisites for the installation machine

Additionally, on the machine where you will perform the installation:

* Kubectl, the same version as your Kubernetes cluster.
* Helm 3.1 or later.


### Prerequisites details
#### Storage
A default storage class is necessary. When using preallocated PersistentVolumes, for example, iSCSI/FC/NFS,
they should be declared with a `storageClassName` as shown:
* Create a default `StorageClass`
  ```yaml
  cat << EOF | kubectl apply -f -
    apiVersion: storage.k8s.io/v1
    kind: StorageClass
    metadata:
      name: datacentre5-nfs
      annotations:
        storageclass.kubernetes.io/is-default-class: "true"
    provisioner: kubernetes.io/no-provisioner
    volumeBindingMode: WaitForFirstConsumer
  EOF
  ```
* Create a `PersistentVolume`
  ```yaml
  cat << EOF | kubectl apply -f -
    apiVersion: v1
    kind: PersistentVolume
    metadata:
      name: pv0001
    spec:
      storageClassName: datacentre5-nfs
      accessModes:
        - ReadWriteOnce
        - ReadWriteMany
      capacity:
        storage: 50Gi
      nfs:
        path: /datapool/k8s/pv0001
        server: 10.10.10.10
      volumeMode: Filesystem
  EOF
  ```

#### Networking

##### Oracle Linux Cloud Native Environment
When installing Verrazzano on Oracle Linux Cloud Native Environment (OLCNE) it's likely you will be using your
own external load balancer services, not those dynamically provided by Kubernetes.
Prior to installation, two load balancers should be deployed, one for management traffic and one
for general traffic.

{{<mermaid align="left">}}
graph LR
	admin([Administrator]) --> |80| A(Management Load Balancer) -->|31380| D[Worker Nodes]
	admin([Administrator]) --> |443| A(Management Load Balancer) -->|31390| D[Worker Nodes]
	user([User]) --> |80| B(General Load Balancer) -->|30080| D[Worker Nodes]
	user([User]) --> |443| B(General Load Balancer) -->|30443| D[Worker Nodes]
{{< /mermaid >}}

* Target Host: Hostnames of Kubernetes worker nodes
* Target Port: See table
* Distribution: Round Robin
* Health Check: TCP

Traffic Type | Service Name | Target Port | Type | Suggested External Port
 ---|---|---|---|---
Management | `istio-ingressgateway` | 31380 | TCP | 80
Management | `istio-ingressgateway` | 31390 | TCP | 443
General | `ingress-controller-nginx-ingress-controller` | 30080 | TCP | 80
General | `ingress-controller-nginx-ingress-controller` | 30443 | TCP | 443

An NGINX example of the management load balancer:
```
load_module /usr/lib64/nginx/modules/ngx_stream_module.so;
events {
  worker_connections 2048;
}
stream {
  upstream backend_http {
    server worker-0.example.com:31380;
    server worker-1.example.com:31380;
    server worker-2.example.com:31380;
  }
  upstream backend_https {
    server worker-0.example.com:31390;
    server worker-1.example.com:31390;
    server worker-2.example.com:31390;
  }
  server {
    listen 80;
    proxy_pass backend_http;
  }
  server {
    listen 443;
    proxy_pass backend_https;
  }
}
```

##### Manual DNS type
When using the DNS type of `manual`, the installer searches the DNS zone you provide for two specific records:

Record | Use
---|---
ingress-mgmt | Set as the `.spec.externalIPs` value of the `istio-ingressgateway` service
ingress-verrazzano | Set as the `.spec.externalIPs` value of the `ingress-controller-nginx-ingress-controller` service

## Installing Dependencies for the installation machine
### Oracle Linux 7
```shell script
sudo yum install -y oracle-olcne-release-el7
sudo yum-config-manager --enable ol7_olcne11 ol7_addons ol7_latest
sudo yum install -y kubectl helm jq openssl curl patch
```
### Other Platforms
