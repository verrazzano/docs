---
title: "Network Traffic"
linkTitle: "Network Traffic"
description: "Verrazzano Network Traffic"
weight: 2
draft: true
---

Network traffic refers to the data flowing across the network.  In the context of this
discussion it is useful to think of network traffic from two perspectives, traffic 
based on direction and traffic related to component types, system or applications. 
Traffic direction is either north-south traffic, which enters and leaves the cluster, 
or east-west traffic, which stays within the cluster. 

First we will discuss getting traffic into the cluster, then how traffic flows once
it is in the cluster. Ingress is an overloaded term that has a few meanings so it needs
to be understood in context.  Sometimes the term is used to mean external access into the 
cluster, as in "ingress to the cluster".  The term is also used for the Kubernetes 
`Ingress` resource. It might also be used to mean network ingress to a container in a pod. 
Presently, it is used to refer to both general ingress into the cluster and the Kubernetes 
Ingress resource.

## Ingress Configuration
During installation, Verrazzano creates the necessary network resources to access both
system components and applications.  The following ingress and load balancers discussion
is in the context of a Verazzano installation.

### LoadBalancer Services
To reach pods from outside a cluster, an external IP must be exposed using a LoadBalancer or NodePort 
service.  Verrazzano creates two LoadBalancer services, one for system component traffic
and another for application traffic. The specifics of how the service gets traffic into the cluster 
depends on the underlying Kubernetes platform.  With Oracle OKE, creating a LoadBalancer type service will
result in an OCI load balancer being created and configured to load balance to a set of pods.

### Ingress for system components
To provide ingress to system components, Verrazzano creates an NGINX Ingress controller, 
which includes an NGINX load balancer.  Verrazzano also creates Kubernetes 
Ingress resource to configure ingress for each system component that requires ingress, like Kibana.
An Ingress resource is used is to specify HTTP/HTTPS routes to Kubernetes services, along 
with an endpoint hostname and a TLS certificate. An Ingress by itself doesn't do anything, 
it is just a resource. An Ingress controller is needed to watch Ingress resources and and 
reconcile them, configuring the underlying Kubernetes load balancer to handle the service 
routing. The NGINX Ingress Controller watches the Ingress resourced and configures
the NGINX load balancer with the Ingress route information.

The NGINX Ingress controller is a LoadBalancer service as seen here:
```
kubectl get service -n ingress-nginx
...
ingress-controller-ingress-nginx-controller           LoadBalancer 
```

Using the OKE example, traffic entering the OCI load balancer is routed to the NGINX load 
balancer, then routed from there to the pods belonging to the services described in the Ingress. 

### Ingress for applications
Verrazzano also provides Ingress into applications but uses an Istio gateway instead of NGINX.
Istio has a `Gateway` resource that provides host and certificate information for traffic coming 
into the mesh. Just like an Ingress needs a corresponding Ingress controller, the same is true 
for the Gateway resource, where there is a corresponding Istio ingress gateway controller.  
However, unlike the Ingress, the Gateway resource doesn't have service routing information.  That is 
handled by the Istio `VirtualService` resource.  So the combination of Gateway and VirtualService is 
basically a superset of Ingress, since VirtualService provides more routing features than Ingress.  
The Gateway provides ingress into the cluster, and VirtualService provides routing rules to services.  

Because Verrazzano doesn't create any applications during installations, there is no need for 
the Gateway and VirtualServices at that time.  However, during installation, Verrazzano does 
create the Istio ingress gateway service, which is a LoadBalancer service, along with the 
Istio egress gateway service, which is a ClusterIP service.  
```
kubectl get service -n istio-system
...
istio-ingressgateway   LoadBalancer 
```
Again referring to the OKE use case,
that means there will another OCI load balancer created, routing traffic to the Istio ingress gateway pod.

### External DNS for System components




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

