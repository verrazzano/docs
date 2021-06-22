---
title: "Networking"
linkTitle: "Networking"
description: "Verrazzano Networking"
weight: 4
draft: true
---

## Overview
Before discussing the specifics of networking in the context of Verrazzano, it is important 
to first explain a few basic Kubernetes networking concepts.  This is a brief summary, 
with many details purposely omitted, so refer to the Kubernetes documentation for a more
in-depth discussion.

### Pods
The Kubernetes network model is a flat network where each pod has its own
IP address. By default, any pod can send IP traffic to any other pod in the cluster and
receive traffic, regardless of the node hosting the pod. All containers within a pod share
the same network namespace and can reach each other using `localhost`.  As a result, containers
within a pod must be aware of port conflicts.  In the context of this document, when we say
pod A is sending data to pod B, it really means that some container in pod A is sending data to 
some container in pod B.  Containers in the pods actually contain the runtime code that listens
on the ports.  Think of a pod as a VM and a container as a process.

### Services
When pods get restarted, they may get a new IP address, so it is not practical for an application to
connect using pod IPs directly.  Kubernetes services have a virtual IP that never changes for the life
of the service.  A service can be configured to load balance across a set of pods, using labels, so 
traffic sent to the service IP will reach a corresponding back-end pod.   When pods are restarted, 
Kubernetes will update the set of back-end pod IPs used by the Service. This virtual IP is called 
a `ClusterIP`, since it exposes the service on an internal cluster IP.  Some services are `headless` 
and do not have a ClusterIP.  Headless services can be used for stateful workloads, like WebLogic domains
and Coherence clusters. 

### Discovering Services
A pod can discover servics within the cluster using ENV vars set by Kubernetes or by DNS name
resolution. Kubernetes provides DNS entries for both services and pods. When pods within the 
cluster need to communicate with other in-cluster pods, they can use the service DNS name, which is 
in the formatof <service-name>.<namespace>.svc.<cluster-domain>.  For example, `catalog.sockshop.svc.cluster.local`.
Kubernetes provides a default DNS server, such as CoreDNS, to provide this name service.  So, if an 
application consisted of multiple services in a cluster, those services would typically be wired 
together using service names.  In the case of a headless services discussed previously, the service
name would translate into the set of available pod IPs mapped to that service.

### External access to pods
So far, we have only discussed networking within a Kubernetes cluster.  To reach pods from outside a cluster,
an external IP must be exposed using a service or type LoadBalancer or NodePort. For a full discussion,
see [Exposing the Service](https://kubernetes.io/docs/concepts/services-networking/connect-applications-service/).
When one of these services is created, it will have a `ExternalIP` field set with the IP that can be used 
to reach the backend-pods.  The service will still load balance pods using a label selector, just like 
the ClusterIP service.  However, the service DNS name cannot be used outside the cluster.  

The specifics of how the service gets traffic into the cluster depends on the underlying Kubernetes platform.  
For OKE, creating a LoadBalancer type service will result in an OCI load balancer being created and configured to
load balance to a set of pods.  For example, assume you have a simple hello world application on OKE with just a pod
 and no service.  If you use the `kubectl expose` command to create a LoadBalancer service for that pod, 
 then a Kubernetes service of type LoadBalancer will get created with label selectors for that pod, along 
 with an OCI load balancer configured to route traffic to the pod.  The end result is that you will have an
 external IP that can then be used to access the pod from outside the cluster.
 
 There is one more important point regarding external services and load balancers.  The simple hello world case above
 just connected an OCI load balancer to a pod.  If you were to use a Kubernetes load balancer, like NGINX, then the OCI
 load balancer would be routing requests to the NGINX pod, which in turn, would be routing the requests to a hello world 
 CluserIP service as we describe next.


### Ingress
Ingress is an overloaded term that has a few meanings in the context of Kubernetes.  Sometimes the term is used to
mean external access to the cluster, as in "ingress to the cluster".  It might also be used to mean network ingress
to a container in a pod.  Both of those meanings are valid, but this discussion is focused on ingress to the cluster.
There is actually a Kubernetes Ingress resource and its purpose is to specify http and https routes to services. An
Ingress by itself doesn't do anything, it is just data. An Ingress controller is needed to watch ingress resources and
and reconcile them, configuring the underlying Kubernetes load balancer, such as NGINX, to handle the service routing.  
This will be discussed in later sections, suffice it to say that there is a difference between services that provide
external access to the cluster, and an ingress, which contains routing rules to services withing the cluster.


Because of this Service IPs or 
names are typically used by clients to connect to pods.
 The service IP will never change forthe life of the service, so applications 
typically use service IPs.  which do not change for the life 

Traffic coming into the cluster must enter through an `ingress`, which is exposed as load balancer
or NodePort Service, see [Services](https://kubernetes.io/docs/concepts/services-networking/connect-applications-service/)
  Egress traffic may be restricted depending on the underlying
CNI or host network configuration.

Kubernetes uses a plug-in model to implement network functionality using the
CNI interface.  

-- Kubernetes Networking
### NGINX Ingress
    Integration with cert-manager
### Istio
### Name Resolution
## Network Traffic
### Overview
### Verrazzano System
### Applications
## Network Security
### Network Policies
### TLS
### Istio Integration

All of the Verrazzano components use the network for communication with
Kubernetes components, other Verrazzano components.
 

Applications typically require some network configuration, such as ingress 

### Ingress for all components
The following table shows all of the pod ports that allow ingress into
Verrazzano components.

| Component  | Pod Port           | From  | Description |
| ------------- |:------------- |:------------- |:----- |:-------------:|
| Verrazzano Application Operator | 9443 | Kubernetes API Server  | Webhook entrypoint 
| Verrazzano Platform Operator | 9443 | Kubernetes API Server  | Webhook entrypoint 
| Verrazzano Console | 8000 | NGINX Ingress |  Access from external client  
| Verrazzano Console | 15090 | Prometheus | Prometheus scraping
| Verrazzano Proxy | 8775 | NGINX Ingress |  Access from external client 
| Verrazzano Proxy | 15090 | Prometheus | Prometheus scraping
| cert-manager| 9402 | Prometheus | Prometheus scraping
| Coherence Operator | 9443 | Prometheus | Webhook entrypoint 
| Elasticsearch | 8775 | NGINX Ingress | Access from external client  
| Elasticsearch | 8775 | Fluentd | Access from Fluentd 
| Elasticsearch | 9200 | Kibana, Internal | Elasticsearch data port  
| Elasticsearch | 9300 | Internal | Elasticsearch cluster port  
| Elasticsearch | 15090 | Prometheus | Envoy metrics scraping 
| Istio control plane | 15012 | Envoy | Envoy access to istiod
| Istio control plane | 15014 | Prometheus | Prometheus scraping
| Istio control plane | 15017 | Kubernetes API Server  | Webhook entrypoint 
| Istio ingress gateway | 8443 | External | Application ingress
| Istio ingress gateway| 15090 | Prometheus | Prometheus scraping
| Istio egress gateway | 8443 | Mesh services | Application egress
| Istio egress gateway| 15090 | Prometheus | Prometheus scraping
| Keycloak| 8080 | NGINX Ingress | Access from external client 
| Keycloak| 15090 | Prometheus | Prometheus scraping
| MySql| 15090 | Prometheus | Prometheus scraping
| MySql| 3306 | Keycloak | Keycloak datastore
| Node exporter| 9100 | Prometheus | Prometheus scraping
| Rancher | 80 | NGINX Ingress | Access from external client
| Rancher | 9443 |  Kubernetes API Server  | Webhook entrypoint 
| Prometheus | 8775 | NGINX Ingress | Access from external client 
| Prometheus | 9090 | Grafana | Acccess for Grafana UI 





### Ingress / Egress
### MultiCluster
### Prometheus
### ES
### Inside Pod (OIDC)
### CoreDNS
### System Components
#### Kubernetes API Server
### Applications
#### Controller to App
### Multicluster
### Network Security
#### Overview
Verrazzano manages and secures network traffic to, from, and between Verrazzano system components 
and deployed applications. We do not manage or secure traffic for the Kubernetes cluster itself, 
or for non-Verrazzano services or applications running in the cluster.

Traffic is secured at two levels in the network stack

1. ISO Layer 3/4 (: We use Kubernetes NetworkPolicy to control what connections can be made to or from pods running in a namespace.
2. ISO Layer 7: We use TLS to provide authentication, confidentiality, and integrity for connections within and between namespaces, and for external connections.

#### NetworkPolicies for L3/L4 security
By default, all pods in a Kubernetes cluster have network access to all other pods.  
Kubernetes has a NetworkPolicy resource that can be applied to pods, providing network 
level 3 and 4 security, restricting both ingress and egress for a set of pods in a namespace, 
see [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies).

{{< alert title="NOTE" color="warning" >}}
Network policies provide additional security but they are enforced only if you install a Kubernetes 
Container Network Interface (CNI) plug-in that enforces them, such as Calico. For an example on OKE, 
see Installing Calico and Setting Up Network Policies.
{{< /alert >}}

During installation, Verrazzano creates NetworkPolicies for all system component, restricting ingress
as required.
A NetworkPolicy can be applied to individual pods with matching labels, or to all pods in the namespace.  
For example, a namespace can be configured to only receive IP traffic from  other pods in the same namespace.  
More fine grained restrictions can also be applied, for example, restricting ingress into the 
Elasticsearch Ingest pod from only the NGINX Ingress controller.


## Istio Integration
### Overview
### Istio Mesh
What does it mean to be in the mesh
Namespace annotation
What is in the mesh
What is outside the mesh
#### mTLS
#### Prometheus Scraping
### Traffic Management
#### Istio Gateway
#### Virtual Service
#### Destination Rule
### Access Control



## Network Policies

## CoreDNS
