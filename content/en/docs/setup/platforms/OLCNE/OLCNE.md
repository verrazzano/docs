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
* Skip the Kubernetes API load balancer ([load balancer](https://docs.oracle.com/en/operating-systems/olcne/1.5/start/install.html#install-lb)).
* Use private CA certificates ([private certs](https://docs.oracle.com/en/operating-systems/olcne/1.5/start/install.html#certs-private)).
* Install a Kubernetes network load balancer implementation, such as [OCI-CCM](https://docs.oracle.com/en/operating-systems/olcne/1.5/lb/oci.html#oci) or [MetalLB](https://docs.oracle.com/en/operating-systems/olcne/1.5/lb/metallb.html#metallb).
* Install a Container Storage Interface Driver, such as [OCI-CCM](https://docs.oracle.com/en/operating-systems/olcne/1.5/storage/oci.html#oci) or [Gluster](https://docs.oracle.com/en/operating-systems/olcne/1.5/storage/gluster.html#gluster).

## Next steps

To continue, see the [Installation Guide]({{< relref "/docs/setup/install/installation.md#install-the-verrazzano-platform-operator" >}}).
