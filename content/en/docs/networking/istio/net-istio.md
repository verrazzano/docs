---
title: "Istio Integration"
linkTitle: "Istio"
description: "Verrazzano Istio Integration" 
weight: 2
draft: true
---

Istio is a feature rich service mesh used by Verrazzano for some traffic management and security.
This document discusses how Verrazzano uses Istio.

## Istio Mesh
A service mesh is an infrastructure layer that provides certain capabilities like security, observabilty, load balancing,
etc. for services used by an application.  Istio defines a service mesh here [Istio Service Mesh](https://istio.io/latest/about/service-mesh/).
What does it mean for a service to be in the mesh?  Basically, it means that there is an Envoy proxy in front of every 
service intercepting inbound and outbound network traffic for that service.  In Kubernetes, that proxy happens to be a sidecar 
running in the all the pods used by the service.  Also, a service refers to a Kubernetes service for this discussion. It is possible
to register non-Kubernetes services, using a `ServiceEntry` but that is not something Verrazzano does.

## Traffic Management
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

### Gateway
The Gateway resource is actually an Envoy proxy, but it is not a sidecar and considered to be part of the mesh.  
What is does really, is provide ingress into the cluster, just like NGINX. In fact, strictly speaking traffic 
is not necessarily routed into the mesh, it is routed a to services which may or may not be in the mesh. For example,
you can use an Istio Gateway and VirtualService to provide ingres to the hello-world application discussed earlier,
where the mesh is not in the picture.  The same  
 

Regarding north-south traffic, requests comes into the mesh and are routed to services using the Gateway and VirtualService
combination.

Verrazzano only configures north-south traffic at this time, though there is nothing precluding
the user from configuring east-west traffic management.  To be clear, this doesn't mean that a Verrazzano application.

## mTLS
## Access Control
## Prometheus

