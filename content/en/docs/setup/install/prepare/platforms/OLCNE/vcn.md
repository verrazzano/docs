---
title: Configure a VCN for OCNE
linkTitle: Configure a VCN for OCNE
description: Set up a virtual cloud network for OCNE clusters on OCI
weight: 3
draft: false
---

Before you can create Oracle Cloud Native Environment (OCNE) clusters on Oracle Cloud Infrastructure (OCI), you'll need to configure a virtual cloud network (VCN) in your OCI compartment. VCNs are software-defined networks that manage access to your cloud resources.

See [Networking Overview](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/overview.htm#network_landing) in the OCI documentation for more information.

You can use the VCN Wizard in the OCI Console to automatically create most of the required network infrastructure. Additional subnets and security rules (described below) must be added manually.

Within your VCN, you'll need:
* Subnets (with security rules)
* Gateways
* Route tables

{{< alert title="NOTE" color="primary" >}}
In addition to the specifications listed, make sure that the VCN is configured to accept the ports and protocols required by Kubernetes. See [Ports and Protocols](https://kubernetes.io/docs/reference/networking/ports-and-protocols/) in the Kubernetes documentation for more information.
{{< /alert >}}

## Subnets

Subnets are subdivisions within a VCN that help to organize configuration settings. All instances within a subnet use the same route table, security lists, and DHCP options. Subnets can be either public or private. For an OCNE cluster, you'll need both public and private subnets, with four subnets in total.

See [Overview of VCNs and Subnets](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/Overview_of_VCNs_and_Subnets.htm#Overview) in the OCI documentation for more information.

Each subnet requires its own set of security rules that establish rules for virtual firewalls. These ingress and egress rules specify the types of traffic (protocol and port) that are allowed in and out of the instances.

See [Security Rules](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securityrules.htm#Security_Rules) in the OCI documentation for more information.


{{< alert title="NOTE" color="primary" >}}
You can use either Network Security Groups (NSGs) or security lists to add security rules to your VCN. We recommend using NSGs whenever possible. See [Comparison of Security Lists and Network Security Groups](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securityrules.htm#comparison) in the OCI documentation.
{{< /alert >}}

### Subnet 1: control plane endpoint

A public subnet for the control plane endpoint that houses an OCI load balancer. The load balancer acts as a reverse proxy for the Kubernetes API server.

In this subnet, create security rules that cover the following traffic:

* Egress: control plane traffic
* Ingress: external access to the Kubernetes API endpoint
* Ingress: ICMP path discovery

<details>
<summary>Security rule examples</summary>

{{< alert title="NOTE" color="primary" >}}
These examples are provided for reference only. Customize your security rules as needed for your environment.
{{< /alert >}}

#### Egress rules

| Destination Type | Destination | Destination Port | Protocol | Description |
|------------------|-------------|------------------|----------|-------------|
| CIDR Block       | 10.0.0.0/29 | 6443             | TCP      | HTTPS traffic to control plane for Kubernetes API server access |

#### Ingress rules

| Destination Type | Destination | Destination Port | Protocol | Description |
|------------------|-------------|------------------|----------|-------------|
| CIDR Block       | 0.0.0.0/0   | 6443             | TCP      | Public access to endpoint OCI load balancer |
| CIDR Block       | 10.0.0.0/16 |                  | ICMP Type 3, Code 4 | Path MTU discovery |
</details>

### Subnet 2: control plane nodes

A private subnet that houses the control plane nodes that run Kubernetes control plane components such as the API Server and the control plane pods.

In this subnet, create security rules that cover the following traffic:

* Egress: node internet access
* Ingress: east-west traffic, originating from within the VCN
* Ingress: control plane endpoint to control plane node access on API endpoint
* Ingress: worker nodes to control plane node access on API endpoint
* Ingress: ETCD client and peer
* Ingress: SSH traffic
* Ingress: control plane to control plane kubelet communication
* Ingress:
* Ingress: Calico rules for control plane and worker nodes for
    * BGP
    * IP-in-IP

<details>
<summary>Security rule examples</summary>

{{< alert title="NOTE" color="primary" >}}
These examples are provided for reference only. Customize your security rules as needed for your environment.
{{< /alert >}}

#### Egress rules

| Destination Type | Destination | Destination Port | Protocol | Description |
|------------------|-------------|------------------|----------|-------------|
| CIDR Block       | 0.0.0.0/0   | All              | All      | Control plane node access to the internet to pull images |

#### Ingress rules

| Destination Type | Destination  | Destination Port | Protocol | Description |
|------------------|--------------|------------------|----------|-------------|
| CIDR Block       | 10.0.0.8/29  | 6443             | TCP      | Kubernetes API endpoint to Kubernetes control plane communication |
| CIDR Block       | 10.0.0.0/29  | 6443             | TCP      | Control plane to control plane (API server port) communication |
| CIDR Block       | 10.0.64.0/20 | 6443             | TCP      | Worker node to Kubernetes control plane (API Server) communication |
| CIDR Block       | 10.0.0.0/29  | 10250            | TCP      | Control plane to control plane node kubelet communication |
| CIDR Block       | 10.0.0.0/29  | 2379             | TCP      | etcd client communication |
| CIDR Block       | 10.0.0.0/29  | 2380             | TCP      | etcd peer communication |
| CIDR Block       | 10.0.0.0/29  | 179              | TCP      | Calico networking (BGP) |
| CIDR Block       | 10.0.64.0/20 | 179              | TCP      | Calico networking (BGP) |
| CIDR Block       | 10.0.0.0/29  |                  | IP-in-IP | Calico networking with IP-in-IP enabled |
| CIDR Block       | 10.0.64.0/20 |                  | IP-in-IP | Calico networking with IP-in-IP enabled |
| CIDR Block       | 10.0.0.0/16  |                  | ICMP Type 3, Code 4 | Path MTU discovery |
| CIDR Block       | 0.0.0.0/0    | 22               | TCP      | Inbound SSH traffic to worker nodes |
| CIDR Block       | 10.0.0.0/16  | All              | TCP      | East-West communication for Kubernetes API server access / DNS access |
</details>

### Subnet 3: service load balancers

A public subnet that houses the service load balancers.

In this subnet, create security rules that cover the following traffic:

* Egress: service load balancer to NodePort on worker nodes
* Ingress: ICMP path discovery
* Ingress: HTTP and HTTPS traffic

<details>
<summary>Security rule examples</summary>

{{< alert title="NOTE" color="primary" >}}
These examples are provided for reference only. Customize your security rules as needed for your environment.
{{< /alert >}}

#### Egress rules

| Destination Type | Destination  | Destination Port | Protocol | Description |
|------------------|--------------|------------------|----------|-------------|
| CIDR Block       | 10.0.64.0/20 | 32000-32767      | TCP      | Access to NodePort services from service load balancers |

#### Ingress rules

| Destination Type | Destination | Destination Port | Protocol | Description |
|------------------|-------------|------------------|----------|-------------|
| CIDR Block       | 0.0.0.0/0   | 80, 443           | TCP      | Incoming traffic to services |
| CIDR Block       | 10.0.0.0/16 |                  | ICMP Type 3, Code 4 | Path MTU discovery |
</details>

### Subnet 4: worker nodes

A private subnet that houses the worker nodes.

In this subnet, create security rules that cover the following traffic:

* Egress: node internet access
* Ingress: east-west traffic, originating from within the VCN
* Ingress: SSH traffic
* Ingress: ICMP path discovery
* Ingress: control plane to kubelet on worker nodes
* Ingress: worker node to worker node
* Ingress: Calico rules for control plane and worker nodes for
    * BGP
    * IP-in-IP
* Ingress: worker nodes to default NodePort ingress

<details>
<summary>Security rule examples</summary>

{{< alert title="NOTE" color="primary" >}}
These examples are provided for reference only. Customize your security rules as needed for your environment.
{{< /alert >}}

#### Egress rules

| Destination Type | Destination | Destination Port | Protocol | Description |
|------------------|-------------|------------------|----------|-------------|
| CIDR Block       | 0.0.0.0/0   | All              | All      | Worker node access to the internet to pull images |

#### Ingress rules

| Destination Type | Destination  | Destination Port | Protocol | Description |
|------------------|------------- |------------------|----------|-------------|
| CIDR Block       | 10.0.0.32/27 | 32000-32767      | TCP      | Incoming traffic from service load balancers (NodePort communication) |
| CIDR Block       | 10.0.0.0/29  | 10250            | TCP      | Control plane node to worker node (kubelet communication) |
| CIDR Block       | 10.0.64.0/20 | 10250            | TCP      | Worker node to worker node (kubelet communication) |
| CIDR Block       | 10.0.0.0/29  | 179              | TCP      | Calico networking (BGP) |
| CIDR Block       | 10.0.64.0/20 | 179              | TCP      | Calico networking (BGP) |
| CIDR Block       | 10.0.0.0/29  |                  | IP-in-IP | Calico networking with IP-in-IP enabled |
| CIDR Block       | 10.0.64.0/20 |                  | IP-in-IP | Calico networking with IP-in-IP enabled |
| CIDR Block       | 10.0.0.0/16  |                  | ICMP Type 3, Code 4 | Path MTU discovery |
| CIDR Block       | 0.0.0.0/0    | 22               | 22       | Inbound SSH traffic to worker nodes |
| CIDR Block       | 10.0.0.0/16  | All              | TCP      | East-West communication for Kubernetes API server access / DNS access |
</details>

## Gateways

Gateways control access from your VCN to other networks. You'll need to configure three different types of gateways:

* [An internet gateway](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingIGs.htm)
* [A NAT gateway](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/NATgateway.htm#NAT_Gateway)
* [A service gateway](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/servicegateway.htm#Access_to_Oracle_Services_Service_Gateway)

You may need to perform some additional configuration to expose the VCN's subnets directly to the internet. See [Access to the Internet](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/overview.htm#Private) in the OCI documentation for details.

## Route tables

Route tables send traffic out of the VCN (for example, to the internet, to your on-premises network, or to a peered VCN) using rules that are similar to traditional network route rules.

See [VCN Route Tables](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingroutetables.htm#Route2) in the OCI documentation for more information.

For OCNE clusters, you'll need to create two route tables:

1. A route table for public subnets that will route stateful traffic to and from the internet gateway. Assign this route table to *both* public subnets.
1. A route table for private subnets that will route stateful traffic to and from the NAT and service gateways. Assign this route table to *both* private subnets.