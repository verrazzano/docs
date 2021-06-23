---
title: "Verrazzano Istio Integration"
linkTitle: "Istio Integration"
description: "Verrazzano Istio Integration" 
weight: 2
draft: true
---

Istio is a feature rich service mesh used by Verrazzano for some traffic management and security.
This document discusses how Verrazzano uses Istio.

## Verrazzano integration with the Istio mesh
A service mesh is an infrastructure layer that provides certain capabilities like security, observabilty, load balancing,
etc. for services used by an application.  Istio defines a service mesh here [Istio Service Mesh](https://istio.io/latest/about/service-mesh/).
What does it mean for a service to be in the mesh?  Basically, it means that there is an Envoy proxy in front of every 
service intercepting inbound and outbound network traffic for that service.  In Kubernetes, that proxy happens to be a sidecar 
running in the all the pods used by the service.  Also, a service refers to a Kubernetes service for this discussion. It is possible
to register non-Kubernetes services, using a `ServiceEntry` but that is not something Verrazzano does.  There are various ways
to put a service in the mesh, this is discussed later.

### Install time Istio integration
During installation, Verrazzano does the following as it relates to Istio:

1. installs Istio
2. enables strict mTLS for the mesh by creating an Istio PeerAuthentication resource, `default.istio-system`
3. creates an Istio egress gateway service as type LoadBalancer, `istio-ingressgateway.istio-system`
4. creates an Istio ingress gateway service as type ClusterIP, `istio-egressgateway.istio-system`
5. configures several Verrazzanao system components to be in the mesh.  

The creation of the ingress gateway service may result in a platform load balancer being created, as it does for OKE.
The egress gateway is just a ClusterIP type service, there is no load balancer involved.  Also, notice
that Verrazzano install does not create any traffic management resources: Gateway, VirtualService, etc.

### System components is in the Mesh
The following Verrazzano components are in the mesh and use mTLS for all service to service communication.
- Elasticsearch
- Fluentd
- Grafana
- Kibana
- Keycloak
- MySQL
- NGINX Ingress Controller
- Prometheus
- Verrazzano API Proxy
- Verrazzano Console
- WebLogic Operator

Some of these components, have mesh related details that are worth noting.

### NGINX
The NGINX ingress controller listens for HTTPS traffic, and provides ingress into the cluster.  NGINX is
configured to do TLS termination of client connnections.  All traffic from NGIX to the mesh services
use mTLS, which means that traffic is fully encrypted from the client to the target back-end services.

### Keycloak and MySQL
Keycloak and MySQL are also in the mesh and use mTLS full network communication.  Since all of the components that use
Keycloak are in the mesh, there is end to end mTLS security for all identity and access management.  The following components
access Keycloak:
- Verrazzano API proxy
- Verrazzano API console
- Elasticsearch
- Prometheus
- Grafana
- Kibana

### Prometheus
Althought Prometheus is in the mesh, it is configured to only use the Envoy sidecar and mTLS when communicating to 
Keycloak for authentication.  All the traffic related to scraping metrics bypasses the sidecar proxy, doesn't use 
 the service IP, but rather connects to the scrape target using the pod IP.  If the scrape target is in the mesh,
 then https is used, otherwise http is used.  For Verrazzano multi-cluster, Prometheus also connects from the admin cluster
 to the Prometheus server in themanaged cluster via the managed cluster NGINX Ingress.  Prometheus in the managed 
 cluster never establishes connections to targets outside the cluster.
 
Since Prometheus is in the mesh, additional configuration is done to allow the Envoy sidecar to be bypassed when scraping pods.
This is done with the annotation `traffic.sidecar.istio.io/includeOutboundIPRanges: <keycloak-service-ip>`.  This causes traffic
bound for Keycloak to go through the Envoy sidecar, and all other traffic to bypass the sidecar.


## Verrazzano network traffic
Istio provides traffic management for both north-south traffic, which enters and leaves the mesh, and east-west traffic,
which stays within the mesh.  Before discussing the traffic pattern details, a few core concepts need to be explained.  

First, there is an Istio `Gateway` resource that provides host and certificate information for traffic coming into the mesh. 
In the same way an Ingress needs a corresponding Ingress controller, the same is true for the Gateway resource, where there 
is a corresponding Ingress gateway controller.  However, unlike the Ingress, the Gateway resource doesn't have service routing 
information.  That is handled by the Istio `VirtualService` resource.  So the combination of Gateway and VirtualService is 
basically a superset of Ingress, since VirtualService provides more routing features than Ingress.  So Gateway provides ingress
into the mesh, and VirtualService provides routing rules to services in the mesh.  Once traffic reaches a given service, there is 
an additional resource, `DestinationRule`, that is applied to the service after the routing has occurred.  The DestinationRule 
allows you to do fine tuning at the target service, such as additional load balancing or disabling mTLS ports.

### North-South traffic
North-south traffic at the minimum requires a Gateway and VirtualService. The Gateway resource is reconciled by a service, 
like the istio-ingressgateway, which in turn is backed by an Envoy proxy pod.  This is not a sidecar and not considered 
to be part of the mesh.  What is does really, is provide ingress into the cluster, just like NGINX. In fact, strictly 
speaking traffic is not necessarily routed into the mesh, it is routed to services which may or may not be in the mesh. 
For example, you can use an Istio Gateway and VirtualService to provide ingress to the hello-world application discussed earlier, 
where the mesh is not in the picture.  Traffic leaving the mesh goes through another Envoy proxy called the istio-egressgateway.
Note that there is no Gateway resource needed for egress.
 
### East-West traffic
East-west traffic is traffic between services in the mesh.  Again, this is one of those areas where technically, you 
can have east-west traffic for services outside the mesh, but then Envoy is not involved and VirtualServices and DestinationRules
have no affect.  To use east-west traffic management, each service in the mesh should have be routed to using a VirtualService
and, optional DestinationRules.  You can still send east-west traffic without either of these resources, but you wont't get any
custom routing or load balancing.

## Istio Security
Istio provides extensive security protection for both authentication and authorization as described here 
[Istio Security](https://istio.io/latest/docs/concepts/security). Access control and mTLS are two security 
features that Verrazzano configures.

### mTLS
Istio can be enabled to use mTLS between services in the mesh, and also between the gateways and sidecar proxies.
There are various options to customize mTLS usage, for example it can be disabled on a per port level.  The Istio control
plane, istiod, is a CA and provides key and certificate rotation for the Envoy proxies, both gateways and sidecar. 

### Access Control
Istio allows you to control access to your workload in the mesh, using the `AuthorizationPolicy` resource. This allows you
to control what services or pods can access your service pods.  Some of these options require mTLS, see 
[Authorization Policy](https://istio.io/latest/docs/reference/config/security/authorization-policy/) for more information.

## Verrazzano and Istio
During installation, Verrazzano does the following as it relates to Istio:

1. installs Istio
2. enables strict mTLS for the mesh by creating an Istio PeerAuthentication resource, `default.istio-system`
3. creates an Istio egress gateway service as type LoadBalancer, `istio-ingressgateway.istio-system`
4. creates an Istio ingress gateway service as type ClusterIP, `istio-egressgateway.istio-system`
5. configures several Verrazzanao system components to be in the mesh.  

The create of the ingress gateway service may result in a platform load balancer being created, as it does for OKE.
The egress gateway is just a ClusterIP type service, there is no load balancer involved.  Also, notice
that Verrazzano install does not create any traffic management resources: Gateway, VirtualService, etc.

### System components is in the Mesh
The following Verrazzano components are in the mesh and use mTLS for all service to service communication.
- Elasticsearch
- Fluentd
- Grafana
- Kibana
- Keycloak
- MySQL
- NGINX Ingress Controller
- Prometheus
- Verrazzano API Proxy
- Verrazzano Console
- WebLogic Operator

Some of these components, have mesh related details that are worth noting.

### NGINX
The NGINX ingress controller listens for HTTPS traffic, and provides ingress into the cluster.  NGINX is
configured to do TLS termination of client connnections.  All traffic from NGIX to the mesh services
use mTLS, which means that traffic is fully encrypted from the client to the target back-end services.

### Keycloak and MySQL
Keycloak and MySQL are also in the mesh and use mTLS full network communication.  Since all of the components that use
Keycloak are in the mesh, there is end to end mTLS security for all identity and access management.  The following components
access Keycloak:
- Verrazzano API proxy
- Verrazzano API console
- Elasticsearch
- Prometheus
- Grafana
- Kibana

### Prometheus
Althought Prometheus is in the mesh, it is configured to only use the Envoy sidecar and mTLS when communicating to 
Keycloak for authentication.  All the traffic related to scraping metrics bypasses the sidecar proxy, doesn't use 
 the service IP, but rather connects to the scrape target using the pod IP.  If the scrape target is in the mesh,
 then https is used, otherwise http is used.  For Verrazzano multi-cluster, Prometheus also connects from the admin cluster
 to the Prometheus server in themanaged cluster via the managed cluster NGINX Ingress.  Prometheus in the managed 
 cluster never establishes connections to targets outside the cluster.
 
Since Prometheus is in the mesh, additional configuration is done to allow the Envoy sidecar to be bypassed when scraping pods.
This is done with the annotation `traffic.sidecar.istio.io/includeOutboundIPRanges: <keycloak-service-ip>`.  This causes traffic
bound for Keycloak to go through the Envoy sidecar, and all other traffic to bypass the sidecar.

### WebLogic Operator
When a WebLogic operator creates a domain, it needs to communicate to the pods in the domain. We put the WebLogic operator
in the mesh so that it can communicate with the domain pods using mTLS.  The alternative would have been to disable mTLS and 
access control for certain domain ports.  As a result, the WebLogic domain must be created in the mesh.  If you do not want 
domains in the mesh then you should take the operator out of the mesh by adding the following label to the WebLogic 
operator deployment to disable sidecar injection:
```
sidecar.istio.io/inject="false"
```

## Verrazzano applications
Before you create a Verrazzano application, you should decide if it should be in the mesh.  You control sidecar injection,
i.e. mesh inclusion,  by labeling the application namespace with `istio-injection=enabled` or `istio-injection=disabled`.  
If the application is in the mesh then mTLS will be used, and you will need to manually modify Istio resources to change
the mTLS mode or add port exceptions.

### WebLogic
When a WebLogic operator creates a domain, it needs to communicate to the pods in the domain. We put the WebLogic operator
in the mesh so that it can communicate with the domain pods using mTLS.  The alternative would have been to disable mTLS and 
access control for certain domain ports.  As a result, the WebLogic domain must be created in the mesh.  If you do not want 
domains in the mesh then you should take the operator out of the mesh by adding the following label to the WebLogic 
operator deployment to disable sidecar injection:
```
sidecar.istio.io/inject="false"
```

### Coherence
Coherence clusters are represented by the `Coherence` resource, and are not in the mesh.  When Verrazzano creates a Coherence
cluster in a namespace that is annotated to do sidecar injection, then it disables injection the Coherence resource using the
`sidecar.istio.io/inject="false"` shown previously.  Furthermore, Verrazzano will create a DestinationRule in the application
namespace to disable mTLS for the the Coherence extend port `9000`.  This allows a service in the mesh to call the Coherence 
extend proxy.  See bob's books for an example at [bobs-books](https://github.com/verrazzano/verrazzano/blob/master/examples/bobs-books).

## Application access control
