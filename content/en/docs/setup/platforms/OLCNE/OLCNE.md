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
Deploy Oracle Cloud Native Environment 1.4 with the Kubernetes module, following instructions from [Oracle Cloud Native Environment: Getting Started](https://docs.oracle.com/en/operating-systems/olcne/).
* Use a single Kubernetes control plane node.
* Skip the Kubernetes API load balancer ([3.4.3](https://docs.oracle.com/en/operating-systems/olcne/1.1/start/install-lb.html)).
* Use private CA certificates ([3.5.3](https://docs.oracle.com/en/operating-systems/olcne/1.1/start/certs-private.html)).
* Install a Container Storage Interface Driver, such as [OCI-CSI](https://docs.oracle.com/en/operating-systems/olcne/1.4/storage/oci.html#oci-install) or [Gluster](https://docs.oracle.com/en/operating-systems/olcne/1.4/storage/gluster.html#gluster).

### Notes

The `oci-csi` module does not elect a default `StorageClass` or configure policies for the `CSIDrivers` that it installs.  A
reasonable choice is the `oci-bv` `StorageClass` with its `CSIDriver` configured with the `File` group policy.

```
kubectl patch sc oci-bv -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
kubectl apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: CSIDriver
metadata:
  name: blockvolume.csi.oraclecloud.com
spec:
  fsGroupPolicy: File
EOF
```

## Prepare for the Verrazzano installation

A Verrazzano Oracle Cloud Native Environment deployment requires:
* Load balancers in front of the worker nodes in the cluster.
* DNS records that reference the load balancers.

**NOTE**: The target ports for the load balancer backends cannot be determined until you install Verrazzano.  
You can create the load balancers before you install, but post-installation configuration is required.

Examples for meeting these requirements follow.

### Load Balancers
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
The following details can be used to create Oracle Cloud Infrastructure load balancers for accessing application and management user interfaces, respectively.
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
## Next steps

To continue, see the [Installation Guide]({{< relref "/docs/setup/install/installation.md#install-the-verrazzano-platform-operator" >}}).
