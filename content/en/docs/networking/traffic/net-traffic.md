---
title: "Network Traffic"
linkTitle: "Network Traffic"
description: "Verrazzano Network Traffic"
weight: 2
draft: true
---

In the context of this discussion, there are two types of network traffic: north-south traffic, 
which enters and leaves the cluster, and east-west traffic, which stays within the cluster.
Verrazzano has different levels of network security based on the type of traffic.  
For example. NetworkPolicies are only applicable to traffic within the cluster.  This
section discusses all of the concepts of network traffic used by Verrazzano.

## Network Configuration during installation
During installation, Verrazzano creates the necessary network resources to access both
system components and applications.  The following discussion is in the context of a 
Verazzano installation.

### LoadBalancer Services
To reach pods from outside a cluster, an external IP must be exposed using a LoadBalancer or NodePort 
service.  Verrazzano creates two LoadBalancer services, one for system component traffic
and another for application traffic. The specifics of how the service gets traffic into the cluster 
depends on the underlying Kubernetes platform.  With Oracle OKE, creating a LoadBalancer type service will
result in an OCI load balancer being created and configured to load balance to a set of pods.

### Ingress into system components
To provide ingress to system components, Verrazzano creates an NGINX Ingress controller, 
which includes an NGINX load balancer.  Verrazzano also creates Kubernetes 
Ingress resource to configure ingress for each system component that requires ingress, like Kibana.
An Ingress resource is used is to specify HTTP/HTTPS routes to Kubernetes services, along 
with an endpoint hostname and a TLS certificate. An Ingress by itself doesn't do anything, 
it is just a resource. An Ingress controller is needed to watch Ingress resources and and 
reconcile them, configuring the underlying Kubernetes load balancer to handle the service 
routing. The NGINX Ingress Controller watches the Ingress resourced and configures
the NGINX load balancer with the Ingress route information.

Using the OKE example, traffic entering the OCI load balancer is routed to the NGINX load 
balancer, then routed from there to the pods belonging to the services described in the Ingress. 



 System components such as Elasticsearch are accessible through the NGINX ingress controller, 
 whereas application ingress into the cluster is provided
by an Istio ingress gateway.

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

