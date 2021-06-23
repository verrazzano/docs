---
title: "Kubernetes Networking"
linkTitle: "Kubernetes"
description: "Kubernetes Networking" 
weight: 1
draft: true
toc_depth: 3
---

Before discussing the specifics of networking in the context of Verrazzano, it is important 
to first explain a few basic Kubernetes networking concepts.  This is a brief summary, 
with many details purposely omitted, so refer to the Kubernetes documentation for a more
in-depth discussion.

## Pods and Containers
The Kubernetes network model is a flat network where each pod has its own
IP address. By default, any pod can send IP traffic to any other pod in the cluster and
receive traffic, regardless of the node hosting the pod. All containers within a pod share
the same network namespace and can reach each other using `localhost`.  As a result, containers
within a pod must be aware of port conflicts.  Containers in the pods have the runtime code 
that optionaly listen on ports.  The IP is at the pod level and set by Kubernetes, whereas ports 
are at the container level and set by the user.  Note that pod ports can have a name and protocol, 
which is used when port discovery is needed. Containers can listen on ports even if they don't 
specify them in the pod, like the Coherence cluster port. 

Following is a pod fragment showing both container ports and pod IP.
```
  spec:
    containers:
    ...
      ports:
      - containerPort: 8080
        name: http
        protocol: TCP
    ...
    podIP: 10.244.0.93
```

There is a type of container called an `init container` that runs during pod startup in sequence, the first init container
runs, then the next, and so forth until they have finished, then the main pod containers start concurrently.  Init containers
don't usually listen on ports, though they sometimes establish connections to other services.  Finally, for pods with multiple
containers, there is typically a single application container, with other containers providing secondary functions and are 
called `sidecars`.  Sometimes these sidecars are injected into the pod at runtime, and the application container might have
no knowledge of the sidecar. 

## Services
The Kubernetes Service resource is an abstraction over a set of back-end pods, where the service 
has a virtual IP that never changes and can be used to access the pods.  This 
virtual IP is called a `ClusterIP`, since it exposes the service on an internal cluster IP.
Kubernetes will update the set of back-end pod IPs used by the Service as the back-end pod changes.
Unlike services, pods can get a new IP address when they are restarted, so it is not practical 
for an application to connect using pod IPs directly.  Applications typically access other 
services using service names, and don't directly use pod IPs.  Some services, called `headless`, 
do not have a ClusterIP and are not load balanced.  Headless services and can be used for 
stateful workloads, like WebLogic domains and Coherence clusters. 

## Discovering Services
A pod can discover servics within the cluster using ENV vars set by Kubernetes or by DNS name
resolution. Kubernetes provides DNS entries for both services and pods.  When pods within the 
cluster need to communicate with other in-cluster pods, they can use the service DNS name, which is 
in the formatof `<service-name>.<namespace>.svc.<cluster-domain>`.  For example, `catalog.sockshop.svc.cluster.local`.
Kubernetes provides a default DNS server, such as CoreDNS, to provide this name service.  So, if an 
application consisted of multiple services in a cluster, those services would typically be wired 
together using service names.  In the case of a headless services discussed previously, the service
name would translate into the set of available pod IPs mapped to that service.

## External access to pods
So far, we have only discussed networking within a Kubernetes cluster.  To reach pods from outside a cluster,
an external IP must be exposed using a service or type LoadBalancer or NodePort. For a full discussion,
see [Exposing the Service](https://kubernetes.io/docs/concepts/services-networking/connect-applications-service/).  
When one of these services is created, it will have a `ExternalIP` field set with the IP that can be used 
to reach the pods selected by that Service.  The service will still load balance pods using a label selector, 
just like the ClusterIP service.  However, the service DNS name cannot be used outside the cluster.  

The specifics of how the service gets traffic into the cluster depends on the underlying Kubernetes platform.  
For OKE, creating a LoadBalancer type service will result in an OCI load balancer being created and configured to
load balance to a set of pods.  For example, assume you have a simple hello world application on OKE with just a pod
 and no service.  If you use the `kubectl expose` command to create a LoadBalancer service for that pod, 
 then a Kubernetes service of type LoadBalancer will get created with label selectors for that pod, along 
 with an OCI load balancer configured to route traffic to the pod.  The end result is that you will have an
 external IP that can then be used to access the pod from outside the cluster.
 
 There is one more important point regarding exposing services and load balancers.  The simple hello world case above
 just connected an OCI load balancer to a pod.  If you were to use a Kubernetes load balancer, like NGINX, then the OCI
 load balancer would be routing requests to the NGINX pod, which in turn, would be routing the requests to the hello world 
pod via a ClusterIP service as we describe in the following section.

## Ingress
Ingress is an overloaded term that has a few meanings in the context of Kubernetes.  Sometimes the term is used to
mean external access to the cluster, as in "ingress to the cluster".  It might also be used to mean network ingress
to a container in a pod.  Both of those meanings are valid, but this discussion is focused on ingress to the cluster.
There is actually a Kubernetes Ingress resource and its purpose is to specify HTTP/HTTPS routes to Kubernetes 
services, along with an endpoint hostname and optional certificate. An Ingress by itself doesn't do anything, it is 
just a resource. An Ingress controller is needed to watch Ingress resources and and reconcile them, configuring the underlying 
Kubernetes load balancer, such as NGINX, to handle the service routing. Verrazzano installs the NGINX Ingress Controller, 
which acts as both the Ingress controller and the load balancer.  This will be discussed in later sections, suffice it 
to say that there is a difference between services that provide external access to the cluster, and an Ingress, which 
contains HTTP/HTTPS routing rules to services within the cluster.
