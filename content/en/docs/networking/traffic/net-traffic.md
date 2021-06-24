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
Again referring to the OKE use case, this means there will another OCI load balancer created, 
routing traffic to the Istio ingress gateway pod.

### External DNS
When you install Verrazzano, you can optionally use an external DNS for your domain.  If you do that,
Verrazzano will not only create the DNS records, using ExternalDNS, but also it will configure your host
name in the Ingress resources. You can then use that host name to access the system components through the 
NGINX Ingress controller.

## System Traffic

### North-South System Traffic

### East-West System Traffic

## Application Traffic

### North-South Application Traffic
The preceding section discussed network configuration during installation.  Once Verrazzano
is installed, you can deploy applications into the Istio mesh.  When doing so, you will
likely need ingress into the application.  As previously mentioned, this can be done with
Istio using the Gateway and VirtualService resources.  Verrazzano will create those resources
for you when you use an IngressTrait in your ApplicationConfiguration.  The Istio
ingress gateway created during installation will be shared by all applications in the mesh,
and the Gateway resource refers to that common ingress gateway.  There is a Gateway/VirtualService
pair created for each IngressTrait. Following is an example of those two resources created by
Verrazzano.

Here is the Gateway, in this case both the host name and certificate were generated
by Verrazzano.
```
apiVersion: v1
items:
- apiVersion: networking.istio.io/v1beta1
  kind: Gateway
  metadata:
   ...
    name: hello-helidon-hello-helidon-appconf-gw
    namespace: hello-helidon
  ...
  spec:
    selector:
      istio: ingressgateway
    servers:
    - hosts:
      - hello-helidon-appconf.hello-helidon.152.67.146.88.nip.io
      port:
        name: https
        number: 443
        protocol: HTTPS
      tls:
        credentialName: hello-helidon-hello-helidon-appconf-cert-secret
        mode: SIMPLE
```

Here is the VirtualService, notice that it refers back to the Gateway, and
that is contains the service routing information.
```
apiVersion: v1
items:
- apiVersion: networking.istio.io/v1beta1
  kind: VirtualService
  metadata:
  ...
    name: hello-helidon-ingress-rule-0-vs
    namespace: hello-helidon
  spec:
    gateways:
    - hello-helidon-hello-helidon-appconf-gw
    hosts:
    - hello-helidon-appconf.hello-helidon.152.67.146.88.nip.io
    http:
    - match:
      - uri:
          prefix: /greet
      route:
      - destination:
          host: hello-helidon
          port:
            number: 8080
```

### East-West Application Traffic
To use east-west traffic management, each service in the mesh should be routed using a VirtualService and an optional 
DestinationRule.  You can still send east-west traffic without either of these resources, but you wont't get any custom 
routing or load balancing.  Verrazzano doesn't configure east-west traffic.  Consider bobbys-front-end in the bob's books example at
[bobs-books-comp.yaml](https://github.com/verrazzano/verrazzano/blob/master/examples/bobs-books/bobs-books-comp.yaml).  
When deploying bob's books, a VirtualService is created for bobby's front-end, because of the IngressTrait, but there are 
no VirtualServices for the other services in the application.  So when bobbys-front-end sends requests to 
bobbys-helidon-stock-application, east-west traffic, the traffic still goes through the Envoy sidecar proxies in 
the source and destination pods, but there is no VirtualService representing bobbys-helidon-stock-application, 
where you could specify a canary deployment or custom load balancing.  This is something you could manually configure, 
but it is not configured by Verrazzano.

