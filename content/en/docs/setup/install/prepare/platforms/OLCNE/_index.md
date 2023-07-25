---
title: Prepare an Oracle Cloud Native Environment Cluster
weight: 1
draft: false
aliases:
  - /docs/setup/platforms/olcne/olcne
---


## Install Oracle Cloud Native Environment
Deploy Oracle Cloud Native Environment with the Kubernetes module, following instructions from [Oracle Cloud Native Environment: Getting Started](https://docs.oracle.com/en/operating-systems/olcne/1.5/start/).
* Install a Kubernetes network load balancer implementation, such as [OCI-CCM](https://docs.oracle.com/en/operating-systems/olcne/1.5/lb/oci.html#oci) or [MetalLB](https://docs.oracle.com/en/operating-systems/olcne/1.5/lb/metallb.html#metallb).
* Install a Container Storage Interface Driver, such as [OCI-CCM](https://docs.oracle.com/en/operating-systems/olcne/1.5/storage/oci.html#oci) or [Gluster](https://docs.oracle.com/en/operating-systems/olcne/1.5/storage/gluster.html#gluster).

### Notes

- The `oci-ccm` module does not elect a default `StorageClass` or configure policies for the `CSIDrivers` that it installs.  A
reasonable choice is the `oci-bv` `StorageClass` with its `CSIDriver` configured with the `File` group policy.
{{< clipboard >}}
<div class="highlight">

    kubectl patch sc oci-bv -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
    kubectl apply -f - <<EOF
    apiVersion: storage.k8s.io/v1
    kind: CSIDriver
    metadata:
      name: blockvolume.csi.oraclecloud.com
    spec:
      fsGroupPolicy: File
    EOF

</div>
{{< /clipboard >}}

- Unless explicitly configured, the `externalip-validation-webhook-service` defaults to blocking all external IP addresses in the cluster, which causes the
Verrazzano installation to fail because an IP address cannot be assigned to an ingress controller. When this situation occurs, the Verrazzano platform operator logs
will contain a message similar to this:
{{< clipboard >}}
<div class="highlight">

    admission webhook "validate-externalip.webhook.svc" denied the request: spec.externalIPs:
        Invalid value: "<external IP address>": externalIP specified is not allowed to use

</div>
{{< /clipboard >}}

   To avoid this error, either disable the `externalip-validation-webhook-service` or configure the service with your load balancer IP addresses prior to installing Verrazzano.
   For more information, see [Enabling Access to all externalIPs](https://docs.oracle.com/en/operating-systems/olcne/1.5/orchestration/external-ips.html#ext-ip-disable).

## Examples
<details>
<summary>Oracle Cloud Infrastructure</summary>
The following is an example of Oracle Cloud Infrastructure that can be used to evaluate Verrazzano installed on Oracle Cloud Native Environment.
If other environments are used, the capacity and configuration should be similar.

You can use the VCN Wizard of the Oracle Cloud Infrastructure Console to automatically create most of the described network infrastructure.
Additional security lists and rules, as detailed in the following sections, need to be added manually.
All Classless Inter-Domain Routing (CIDR) values provided are examples and can be customized as required.

### Virtual Cloud Network (for example, CIDR 10.0.0.0/16)
**Public Subnet for Load Balancer (for example, CIDR 10.0.0.0/24)**

Security List / Ingress Rules

| Stateless | Destination | Protocol | Source Ports | Destination Ports | Type & Code | Description |
|-----------|-------------|----------|--------------|-------------------|-------------|-------------|
| No       | `0.0.0.0/0`  | ICMP    |               |                   | 3, 4      | ICMP errors        |
| No       | `10.0.0.0/16`| ICMP    |               |                   | 3         | ICMP errors        |
| No       | `0.0.0.0/0`  | TCP     | All           | 22                |           | SSH                |
| No       | `0.0.0.0/0`  | TCP     | All           | 443               |           | HTTPS load balancer |


Security List / Egress Rules

|Stateless| Destination| Protocol| Source Ports| Destination Ports |Type & Code| Description        |
|---------|-----------|--------|------------|-------------------|-----------|-------------------|
|No       |`10.0.1.0/24`|TCP     |All         | 22                |           |SSH                |
|No       |`10.0.1.0/24`|TCP     |All         | 31443             |           |HTTPS load balancer|
|No       |`10.0.1.0/24`|TCP     |All         | 32443             |           |HTTPS load balancer|

**Private Subnet for Kubernetes Cluster (for example, CIDR 10.0.1.0/24)**

Security List / Ingress Rules

|Stateless| Destination   | Protocol | Source Ports | Destination Ports | Type & Code |Description          |
|---------|---------------|----------|--------------|-------------------|------------|---------------------|
|No       | `0.0.0.0/0`   | ICMP     |              |                   | 3, 4       |ICMP errors          |
|No       | `10.0.0.0/16` | ICMP     |              |                   | 3          |ICMP errors          |
|No       | `10.0.0.0/16` | TCP      | All          | 22                |            |SSH                  |
|No       | `10.0.0.0/24` | TCP      | All          | 31443             |            |HTTPS load balancer  |
|No       | `10.0.0.0/24` | TCP      | All          | 32443             |            |HTTPS load balancer  |
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

### Compute Instances

The following compute resources adhere to the guidelines provided in [Oracle Cloud Native Environment: Getting Started](https://docs.oracle.com/en/operating-systems/olcne/).
The attributes indicated (for example, Subnet, RAM, Shape, and Image) are recommendations that have been tested.
Other values can be used if required.

| Role                          | Subnet  | Suggested RAM | Compatible VM Shape | Compatible VM Image |
|-------------------------------|---------|---------------|---------------------|---------------------|
| SSH Jump Host                 | Public  | 8 GB           | VM.Standard3.Flex    | Oracle Linux 7.9    |
| Oracle Cloud Native Environment Operator Host           | Private | 16 GB          | VM.Standard3.Flex    | Oracle Linux 7.9    |
| Kubernetes Control Plane Node | Private | 32 GB          | VM.Standard3.Flex    | Oracle Linux 7.9    |
| Kubernetes Worker Node 1      | Private | 32 GB          | VM.Standard3.Flex    | Oracle Linux 7.9    |
| Kubernetes Worker Node 2      | Private | 32 GB          | VM.Standard3.Flex    | Oracle Linux 7.9    |
| Kubernetes Worker Node 3      | Private | 32 GB          | VM.Standard3.Flex    | Oracle Linux 7.9    |
</details>

## Next steps

To continue, see the [Installation Guide]({{< relref "/docs/setup/install/" >}}).
