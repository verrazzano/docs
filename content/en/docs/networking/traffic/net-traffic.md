---
title: "Network Traffic"
linkTitle: "Network Traffic"
description: "Verrazzano Network Traffic"
weight: 2
draft: true
---

Network traffic refers to the data flowing across the network.  In the context of this
discussion, it is useful to think of network traffic from two perspectives, traffic 
based on direction and traffic related to component types, system or applications. 
Traffic direction is either north-south traffic, which enters and leaves the cluster, 
or east-west traffic, which stays within the cluster. 

First, we will discuss getting traffic into the cluster, then how traffic flows once
it is in the cluster. 

## Ingress
Ingress is an overloaded term that has a few meanings so it needs
to be understood in context.  Sometimes the term is used to mean external access into the 
cluster, as in "ingress to the cluster".  The term is also used for the Kubernetes 
`Ingress` resource. It might also be used to mean network ingress to a container in a pod. 
Presently, it is used to refer to both general ingress into the cluster and the Kubernetes 
Ingress resource.

During installation, Verrazzano creates the necessary network resources to access both
system components and applications.  The following ingress and load balancers discussion
is in the context of a Verrazzano installation.

### LoadBalancer Services
To reach pods from outside a cluster, an external IP must be exposed using a LoadBalancer or NodePort 
service.  Verrazzano creates two LoadBalancer services, one for system component traffic
and another for application traffic. The specifics of how the service gets traffic into the cluster 
depends on the underlying Kubernetes platform.  With Oracle OKE, creating a LoadBalancer type service will
result in an OCI load balancer being created and configured to load balance to a set of pods.

### Ingress for system components
To provide ingress to system components, Verrazzano installs a NGINX Ingress Controller, 
which includes a NGINX load balancer.  Verrazzano also creates Kubernetes 
Ingress resources to configure ingress for each system component that requires ingress.
An Ingress resource is used is to specify HTTP/HTTPS routes to Kubernetes services, along 
with an endpoint hostname and a TLS certificate. An Ingress by itself doesn't do anything, 
it is just a resource. An Ingress controller is needed to watch Ingress resources and
reconcile them, configuring the underlying Kubernetes load balancer to handle the service 
routing. The NGINX Ingress Controller processes Ingress resources and configures NGINX with 
the Ingress route information, etc.

The NGINX Ingress Controller is a LoadBalancer service as seen here:
```
kubectl get service -n ingress-nginx
...
ingress-controller-ingress-nginx-controller           LoadBalancer 
```

Using the OKE example, traffic entering the OCI load balancer is routed to the NGINX load 
balancer, then routed from there to the pods belonging to the services described in the Ingress. 

### Ingress for applications
Verrazzano also provides Ingress into applications, but uses an Istio ingress gateway, which is
an Envoy proxy, instead of NGINX.  Istio has a `Gateway` resource that provides load balancer information
such as hosts, ports, and certificates for traffic coming into the mesh. 
See [Istio Gateway](https://istio.io/latest/docs/reference/config/networking/gateway/) for more information.  Just as an 
Ingress needs a corresponding Ingress controller, the same is true for the Gateway resource, where there is a 
corresponding Istio ingress gateway controller. However, unlike the Ingress, the Gateway 
resource doesn't have service routing information.  That is 
handled by the Istio `VirtualService` resource.  The combination of Gateway and VirtualService is 
basically a superset of Ingress, since the combination provides more features than Ingress. 
In summary, the Istio ingress gateway provides ingress to the cluster using information from both
the Gateway and VirtualService resources.

Because Verrazzano doesn't create any applications during installations, there is no need to
create a Gateway and VirtualService at that time.  However, during installation, Verrazzano does 
create the Istio ingress gateway, which is a LoadBalancer service, along with the 
Istio egress gateway, which is a ClusterIP service.  
```
kubectl get service -n istio-system
...
istio-ingressgateway   LoadBalancer 
```
Again referring to the OKE use case, this means there will another OCI load balancer created, 
routing traffic to the Istio ingress gateway pod, i.e., the Envoy proxy.

### External DNS
When you install Verrazzano, you can optionally specify an external DNS for your domain.  If you do that,
Verrazzano will not only create the DNS records, using ExternalDNS, but also it will configure your host
name in the Ingress resources. You can then use that host name to access the system components through the 
NGINX Ingress Controller.

## System Traffic
System traffic includes all traffic that enters and leaves system pods.

### North-South System Traffic
North-south traffic includes all system traffic that enters or leaves a Kubernetes cluster.

#### Ingress
The following list shows which Verrazzano system components are accessed through the NGINX Ingress Controller
from a client external to the cluster.

- Elasticsearch
- Keycloak
- Kibana
- Grafana
- Prometheus
- Rancher
- Verrazzano Console 
- Verrazzano API

#### Egress
The following tables shows Verrazzano system components that initiate requests to a destination
outside the cluster.

| Component  | Destination | Description |
| ------------- |:------------- |:------------- 
| cert-manager | Let's Encrypt | Get signed certificate
| Elasticsearch | Keycloak | OIDC sidecar calls Keycloak for authentication which includes redirects
| ExternalDNS | OCI | Create and Delete DNS entries in OCI DNS
| Fluentd | Elasticsearch | Fluentd on the managed cluster calls Elasticsearch on the admin cluster
| Grafana | Keycloak | OIDC sidecar calls Keycloak for authentication which includes redirects
| Kibana | Keycloak | OIDC sidecar calls Keycloak for authentication which includes redirects
| Prometheus | Prometheus | Prometheus on admin cluster scrapes metrics from Prometheus on managed cluster
| Rancher Agent | Rancher | Rancher agent on managed cluster sends requests to Rancher on admin cluster
| Verrazzano API Proxy | Keycloak | API proxy on the managed cluster calls Keycloak on the admin cluster
| Verrazzano Console | Verrazzano API proxy | Console on admin cluster calls API proxy on managed cluster
| Verrazzano Console | Verrazzano API proxy | Console on admin cluster calls API proxy on managed cluster
| Verrazzano Platform Operator | Kubernetes API server | MC agent on managed cluster calls API server on admin cluster

### East-West System Traffic
The following tables shows Verrazzano system components that send traffic to a destination
inside the cluster.  The destinations include any Verrazzano applications, with the following exceptions:
- Usage of CoreDNS: It can be assumed that any pod in the cluster can access CoreDNS for name resolution.
- Envoy to Istiod: The Envoy proxies all make requests to the Istio control plane to get dynamic configuration, etc.
This includes both the gateways and the mesh sidecar proxies. That traffic is not shown. 
- Traffic within a component is not shown, for example, traffic between
Elasticsearch pods.
- Prometheus scraping traffic is shown in the second table

| Component  | Destination | Description |
| ------------- |:------------- |:-------------
| cert-manager | Kubernetes API server | Perform CRUD operations on Kubernetes resources
| Elasticsearch | Keycloak | OIDC sidecar calls Keycloak for token authentication
| Fluentd | Elasticsearch | Fluentd sends data to Elasticsearch 
| Grafana | Prometheus | UI for Prometheus data
| Grafana | Keycloak | OIDC sidecar calls Keycloak for token authentication
| Kibana | Elasticsearch | UI for Elasticsearch
| Kibana | Keycloak | OIDC sidecar calls Keycloak for token authentication
| NGINX Ingress Controller | Kubernetes API server | Perform CRUD operations on Kubernetes resources
| Istio | Kubernetes API server | Perform CRUD operations on Kubernetes resources
| Prometheus | Keycloak | OIDC sidecar calls Keycloak for token authentication
| Rancher | Kubernetes API server | Perform CRUD operations on Kubernetes resources
| Verrazzano API Proxy | Kubernetes API server | Perform CRUD operations on Kubernetes resources
| Verrazzano Application Operator | Kubernetes API server | Perform CRUD operations on Kubernetes resources
| Verrazzano Monitoring Operator | Kubernetes API server | Perform CRUD operations on Kubernetes resources
| Verrazzano Operator | Kubernetes API server | Perform CRUD operations on Kubernetes resources
| Verrazzano Platform Operator | Kubernetes API server | Perform CRUD operations on Kubernetes resources
| Verrazzano Platform Operator | Rancher| Register managed cluster with Rancher


#### Prometheus scraping traffic
This table shows Prometheus traffic for each system component scrape target. 

 Target | Description |
|:------------- |:------------- 
| cadvisor | Kubernetes metrics
| Elasticsearch | Envoy metrics
| Grafana | Envoy metrics
| Istiod | Istio control plane metrics
| Istiod | Envoy metrics
| Istio egress gateway | Envoy metrics
| Istio ingress gateway | Envoy metrics
| Keycloak |Envoy metrics
| Kibana | Envoy metrics
| MySQL | Envoy metrics
| NGINX Ingress Controller | Envoy metrics
| NGINX Ingress Controller | NGINX metrics
| NGINX default back-end | Envoy metrics
| Node exporter | Node metrics
| Prometheus | Envoy metrics
| Prometheus | Prometheus metrics
| Verrazzano console | Envoy metrics
| Verrazzano API | Envoy metrics
| WebLogic operator | Envoy metrics

#### Webhooks
Several of the system components are controllers, and some of those have webhooks.
Webhooks are called by the Kubernetes API server on a component HTTPS port
to validate or mutate API payloads before they reach the API server.

The following components use webhooks:
- cert-manager
- Coherence Operator
- Istio
- Rancher
- Verrazzano Application Operator
- Verrazzano Platform Operator

#### Health Checks
Each Kubernetes node has a kubelet that does health checks on pods using probes, such
as liveness probes.  This is something that you should be aware of, but no action
is required on your part.  Verrazzano has no involvement with Kubelet health checks,
and they are not affected by NetworkPolices.

## Application Traffic
Application traffic includes all traffic to and from Verrazzano applications. 

### North-South Application Traffic
Once Verrazzano is installed, you can deploy applications into the Istio mesh.  When doing so, you will
likely need ingress into the application.  As previously mentioned, this can be done with
Istio using the Gateway and VirtualService resources.  Verrazzano will create those resources
for you when you use an IngressTrait in your ApplicationConfiguration.  The Istio
ingress gateway created during installation will be shared by all applications in the mesh,
and the Gateway resource is bound to the Istio ingress gateway that was created
during installation.  This is done by the selector field in the Gateway:
```
   selector:
     istio: ingressgateway
```

Verrazzano creates a Gateway/VirtualService pair for each IngressTrait. 
Following is an example of those two resources created by Verrazzano.

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
      - hello-helidon-appconf.hello-helidon.1.2.3.4.nip.io
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
    - hello-helidon-appconf.hello-helidon.1.2.3.4.nip.io
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
To manage east-west traffic, each service in the mesh should be routed using a VirtualService and an optional 
DestinationRule.  You can still send east-west traffic without either of these resources, but you won’t get any custom 
routing or load balancing.  Verrazzano doesn't configure east-west traffic.  Consider bobbys-front-end in the bob's books example at
[bobs-books-comp.yaml](https://github.com/verrazzano/verrazzano/blob/master/examples/bobs-books/bobs-books-comp.yaml). 
When deploying bob's books, a VirtualService is created for bobby's front-end, because of the IngressTrait, but there are 
no VirtualServices for the other services in the application.  When bobbys-front-end sends requests to 
bobbys-helidon-stock-application, east-west traffic, the traffic still goes to bobbys-helidon-stock-application through 
the Envoy sidecar proxies in the source and destination pods, but there is no VirtualService representing 
bobbys-helidon-stock-application, where you could specify a canary deployment or custom load balancing.  This 
is something you could manually configure, but it is not configured by Verrazzano.

## Proxies
Verrazzano uses network proxies in multiple places.  The two proxies products used are Envoy and NGINX.
The following table shows which proxies are used and what pod they run in.

| Usage  | Proxy | Pod | Namespace | Description |
| ------------- |:------------- |:------------- |:------------- |:-------------
| System ingress | NGINX | ingress-controller-ingress-nginx-controller-* | ingress-nginx | Provides external access to Verrazzano system components
| OIDC proxy sidecar | NGINX | vmi-system-es-ingest-* | verrazzano-system | Elasticsearch authentication 
| OIDC proxy sidecar | NGINX | vmi-system-kibana--* | verrazzano-system | Elasticsearch authentication 
| OIDC proxy sidecar | NGINX | vmi-system-prometheus-* | verrazzano-system | Elasticsearch authentication 
| OIDC proxy sidecar | NGINX | vmi-system-grafana-* | verrazzano-system | Elasticsearch authentication 
| OIDC proxy sidecar | NGINX | verrazzano-api-* | verrazzano-system | Verrazzano API server that proxies to Kubernetes API server
| Application ingress | Envoy | istio-ingressgateway-* | istio-system | Provides external access to Verrazzano applications
| Application egress | Envoy | istio-egressgateway-* | istio-system | Provides control of application egress traffic
| Istio mesh sidecar | Envoy  | ingress-controller-ingress-nginx-controller-* | ingress-nginx | NGINX Ingress Controller in the Istio mesh
| Istio mesh sidecar | Envoy  | ingress-controller-ingress-nginx-defaultbackend-* | ingress-nginx | NGINX default backend in the Istio mesh
| Istio mesh sidecar | Envoy  | fluentd-* | verrazzano-system | Fluentd in the Istio mesh
| Istio mesh sidecar | Envoy  | keycloak-* | keycloak | Keycloak in the Istio mesh
| Istio mesh sidecar | Envoy  | mysql-* | keycloak | MySQL used by Keycloak in the Istio mesh
| Istio mesh sidecar | Envoy | verrazzano-api-* | verrazzano-system | Verrazzano API in the Istio mesh
| Istio mesh sidecar | Envoy | verrazzano-console-* | verrazzano-system | Verrazzano console in the Istio mesh
| Istio mesh sidecar | Envoy  | vmi-system-es-master-* | verrazzano-system | Elasticsearch in the Istio mesh 
| Istio mesh sidecar | Envoy  | vmi-system-es-data-* | verrazzano-system | Elasticsearch in the Istio mesh 
| Istio mesh sidecar | Envoy  | vmi-system-es-ingest-* | verrazzano-system | Elasticsearch in the Istio mesh 
| Istio mesh sidecar | Envoy  | vmi-system-kibana--* | verrazzano-system | Kibana in the Istio mesh 
| Istio mesh sidecar | Envoy  | vmi-system-prometheus-* | verrazzano-system | Prometheus in the Istio mesh  
| Istio mesh sidecar | Envoy  | vmi-system-grafana-* | verrazzano-system | Grafana in the Istio mesh
| Istio mesh sidecar | Envoy  | weblogic-operator-* | verrazzano-system | WebLogic operator in the Istio mesh

## Hybrid Traffic
Some Verrazzano components have mixed traffic accross the aforementioned categories and traffic directions. Those
components are the Verrazzano API proxy, the OIDC proxy, Prometheus, WebLogic, and Prometheus.  Some of this 
information is also discussed in other sections of the document, but summarized here.

### Verrazzano API proxy

