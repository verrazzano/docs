---
title: "Network Traffic"
description: ""
weight: 3
draft: false
---

Network traffic refers to the data flowing across the network.  In the context of this
document, it is useful to think of network traffic from two perspectives: traffic
based on direction and traffic related to component types, system, or applications.
Traffic direction is either north-south traffic, which enters and leaves the cluster,
or east-west traffic, which stays within the cluster.

First is a description of getting traffic into the cluster, then how traffic flows after
it is in the cluster.

## Ingress
Ingress is an overloaded term, so it needs
to be understood in context.  Sometimes the term means external access into the
cluster, as in "ingress to the cluster."  The term also refers to the Kubernetes
Ingress resource. In addition, it might be used to mean network ingress to a container in a Pod.
Here, it's used to refer to both general ingress into the cluster and the Kubernetes
Ingress resource.

During installation, Verrazzano creates the necessary network resources to access both
system components and applications.  The following ingress and load balancers descriptions
are in the context of a Verrazzano installation.

### LoadBalancer Services
To reach Pods from outside a cluster, an external IP address must be exposed using a LoadBalancer or NodePort
service.  Verrazzano creates two LoadBalancer services, one for system component traffic
and another for application traffic. The specifics of how the service gets traffic into the cluster
depends on the underlying Kubernetes platform.  With Oracle Cloud Infrastructure Container Engine for Kubernetes (OKE),
creating a LoadBalancer type service will
result in an Oracle Cloud Infrastructure load balancer being created and configured to load balance to a set of Pods.

### Ingress for system components
To provide ingress to system components, Verrazzano installs a Ingress NGINX Controller,
which includes a NGINX load balancer.  Verrazzano also creates Kubernetes
Ingress resources to configure ingress for each system component that requires ingress.
An Ingress resource is used is to specify HTTP/HTTPS routes to Kubernetes services, along
with an endpoint host name and a TLS certificate. An Ingress by itself doesn't do anything;
it is just a resource. An ingress controller is needed to watch Ingress resources and
reconcile them, configuring the underlying Kubernetes load balancer to handle the service
routing. The Ingress NGINX Controller processes Ingress resources and configures NGINX with
the ingress route information, and such.

The Ingress NGINX Controller is a LoadBalancer service, as seen here:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get service -n ingress-nginx

# Sample output
ingress-controller-ingress-nginx-controller           LoadBalancer
```

</div>
{{< /clipboard >}}


Using the OKE example, traffic entering the Oracle Cloud Infrastructure load balancer is routed to the NGINX load
balancer, then routed from there to the Pods belonging to the services described in the Ingress.

### Ingress for applications
Verrazzano also provides ingress into applications, but uses an Istio ingress gateway, which is
an Envoy proxy, instead of NGINX.  Istio has a Gateway resource that provides load balancer information,
such as hosts, ports, and certificates for traffic coming into the mesh.
For more information, see [Istio Gateway](HTTPS://istio.io/latest/docs/reference/config/networking/gateway/).  Just as an
Ingress needs a corresponding Ingress controller, the same is true for the Gateway resource, where there is a
corresponding Istio ingress gateway controller. However, unlike the Ingress, the Gateway
resource doesn't have service routing information.  That is
handled by the Istio VirtualService resource.  The combination of Gateway and VirtualService is
basically a superset of Ingress, because the combination provides more features than Ingress.
In summary, the Istio ingress gateway provides ingress to the cluster using information from both
the Gateway and VirtualService resources.

Because Verrazzano doesn't create any applications during installations, there is no need to
create a Gateway and VirtualService at that time.  However, during installation, Verrazzano does
create the Istio ingress gateway, which is a LoadBalancer service, along with the
Istio egress gateway, which is a ClusterIP service.  
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get service -n istio-system

# Sample output
istio-ingressgateway   LoadBalancer
```

</div>
{{< /clipboard >}}


Again, referring to the OKE use case, this means that there will another Oracle Cloud Infrastructure load balancer created,
routing traffic to the Istio ingress gateway Pod, for example, the Envoy proxy.

### External DNS
When you install Verrazzano, you can optionally specify an external DNS for your domain.  If you do that,
Verrazzano will not only create the DNS records, using ExternalDNS, but also it will configure your host
name in the Ingress resources. You can then use that host name to access the system components through the
Ingress NGINX Controller.

## System traffic
System traffic includes all traffic that enters and leaves system Pods.

### North-south system traffic
North-south traffic includes all system traffic that enters or leaves a Kubernetes cluster.

#### Ingress
The following lists the Verrazzano system components which are accessed through the Ingress NGINX Controller
from a client external to the cluster:

- argoCD
- OpenSearch
- Keycloak
- OpenSearch Dashboards
- Grafana
- Prometheus
- Rancher
- Verrazzano Console
- Verrazzano API

#### Egress
The following table shows Verrazzano system components that initiate requests to a destination
outside the cluster.

| Component  | Destination | Description |
| ------------- |:------------- |:-------------
| argoCD | Git webhooks (GitHub, GitLab, Bitbucket) | Argo CD connection to Git webhooks for connecting to Git repositories.
| cert-manager | Let's Encrypt | Gets signed certificate.
| ExternalDNS | External DNS | Creates and deletes DNS entries in an external DNS.
| Fluentd | OpenSearch | Fluentd on the managed cluster calls OpenSearch on the admin cluster.
| Prometheus | Prometheus | Prometheus on the admin cluster scrapes metrics from Prometheus on the managed cluster.
| Rancher Agent | Rancher | Rancher agent on the managed cluster sends requests to Rancher on the admin cluster.
| Verrazzano Authentication Proxy | Keycloak | Calls Keycloak for authentication, which includes redirects.
| Verrazzano Platform Operator | Kubernetes API server | Multicluster agent on the managed cluster calls API server on the admin cluster.

### East-west system traffic
The following tables show Verrazzano system components that send traffic to a destination
inside the cluster, with the following exceptions:
- Usage of CoreDNS: It can be assumed that any Pod in the cluster can access CoreDNS for name resolution.
- Envoy to Istiod: The Envoy proxies all make requests to the Istio control plane to get dynamic configuration, and such.
This includes both the gateways and the mesh sidecar proxies. That traffic is not shown.
- Traffic within a component is not shown, for example, traffic between
OpenSearch Pods.
- Prometheus scraping traffic is shown in the second table.

| Component  | Destination | Description |
| ------------- |:------------- |:-------------
| argoCD | Kubernetes API server | Performs CRUD operations on Kubernetes resources.
| cert-manager | Kubernetes API server | Performs CRUD operations on Kubernetes resources.
| Fluentd | OpenSearch | Fluentd sends data to OpenSearch.
| Grafana | Prometheus | Console for Prometheus data.
| OpenSearch Dashboards | OpenSearch | Console for OpenSearch.
| Ingress NGINX Controller | Kubernetes API server | Performs CRUD operations on Kubernetes resources.
| Istio | Kubernetes API server | Performs CRUD operations on Kubernetes resources.
| Rancher | Kubernetes API server | Performs CRUD operations on Kubernetes resources.
| Verrazzano Authentication Proxy | Keycloak | Calls Keycloak for token authentication.
| Verrazzano Authentication Proxy | VMI components | Access consoles for OpenSearch Dashboards, Grafana, and such.
| Verrazzano Authentication Proxy | Kubernetes API server | Performs CRUD operations on Kubernetes resources.
| Verrazzano Application Operator | Kubernetes API server | Performs CRUD operations on Kubernetes resources.
| Verrazzano Monitoring Operator | Kubernetes API server | Performs CRUD operations on Kubernetes resources.
| Verrazzano Operator | Kubernetes API server | Performs CRUD operations on Kubernetes resources.
| Verrazzano Platform Operator | Kubernetes API server | Performs CRUD operations on Kubernetes resources.
| Verrazzano Platform Operator | Rancher| Registers the managed cluster with Rancher.


#### Prometheus scraping traffic
This table shows Prometheus traffic for each system component scrape target.

 Target | Description |
|:------------- |:-------------
| argoCD | Envoy metrics
| cadvisor | Kubernetes metrics
| Grafana | Envoy metrics
| Istiod | Istio control plane metrics
| Istiod | Envoy metrics
| Istio egress gateway | Envoy metrics
| Istio ingress gateway | Envoy metrics
| Keycloak |Envoy metrics
| MySQL | Envoy metrics
| Ingress NGINX Controller | Envoy metrics
| Ingress NGINX Controller | NGINX metrics
| NGINX default back end | Envoy metrics
| Node exporter | Node metrics
| OpenSearch | Envoy metrics
| OpenSearch Dashboards | Envoy metrics
| Prometheus | Envoy metrics
| Prometheus | Prometheus metrics
| Verrazzano Console | Envoy metrics
| Verrazzano API | Envoy metrics
| WebLogic operator | Envoy metrics

#### Webhooks
Several of the system components are controllers and some of those have webhooks.
Webhooks are called by the Kubernetes API server on a component HTTPS port
to validate or mutate API payloads before they reach the API server.

The following components use webhooks:
- cert-manager
- Coherence Operator
- Istio
- Rancher
- Verrazzano Application Operator
- Verrazzano Platform Operator

## Application traffic
Application traffic includes all traffic to and from Verrazzano applications.

### North-south application traffic
After Verrazzano is installed, you can deploy applications into the Istio mesh.  When doing so, you will
likely need ingress into the application.  As previously mentioned, this can be done with
Istio using the Gateway and VirtualService resources.  Verrazzano will create those resources
for you when you use an IngressTrait in your ApplicationConfiguration.  The Istio
ingress gateway created during installation will be shared by all applications in the mesh,
and the Gateway resource is bound to the Istio ingress gateway that was created
during installation.  This is done by the selector field in the Gateway.
{{< clipboard >}}
<div class="highlight">

```
   selector:
     istio: ingressgateway
```

</div>
{{< /clipboard >}}

Verrazzano creates a Gateway/VirtualService pair for each IngressTrait.
Following is an example of those two resources created by Verrazzano.

Here is the Gateway; in this case both the host name and certificate were generated
by Verrazzano.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: v1
items:
- apiVersion: networking.istio.io/v1beta1
  kind: Gateway
  metadata:
   ...
    name: hello-helidon-hello-helidon-gw
    namespace: hello-helidon
  ...
  spec:
    selector:
      istio: ingressgateway
    servers:
    - hosts:
      - hello-helidon-appconf.hello-helidon.1.2.3.4.nip.io
      port:
        name: HTTPS
        number: 443
        protocol: HTTPS
      tls:
        credentialName: hello-helidon-hello-helidon-appconf-cert-secret
        mode: SIMPLE
```

</div>
{{< /clipboard >}}

Here is the VirtualService; notice that it refers back to the Gateway and
that it contains the service routing information.
{{< clipboard >}}
<div class="highlight">

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
    - hello-helidon-hello-helidon-gw
    hosts:
    - hello-helidon-appconf.hello-helidon.1.2.3.4.nip.io
    HTTP:
    - match:
      - uri:
          prefix: /greet
      route:
      - destination:
          host: hello-helidon
          port:
            number: 8080
```

</div>
{{< /clipboard >}}

### East-west application traffic
To manage east-west traffic, each service in the mesh should be routed using a VirtualService and an optional
DestinationRule.  You can still send east-west traffic without either of these resources, but you won’t get any custom
routing or load balancing.  Verrazzano doesn't configure east-west traffic.  Consider `bobbys-front-end` in the Bob's Books example at
[bobs-books-comp.yaml]( {{< release_source_url path=examples/bobs-books/bobs-books-comp.yaml >}} ).
When deploying Bob's Books, a VirtualService is created for `bobbys-front-end`, because of the IngressTrait, but there are
no VirtualServices for the other services in the application.  When `bobbys-front-end` sends requests to
`bobbys-helidon-stock-application`, this east-west traffic still goes to `bobbys-helidon-stock-application` through
the Envoy sidecar proxies in the source and destination Pods, but there is no VirtualService representing
`bobbys-helidon-stock-application` where you could specify a canary deployment or custom load balancing.  This
is something you could configure manually, but it is not configured by Verrazzano.

## Proxies
Verrazzano uses network proxies in multiple places.  The two proxy products are Envoy and NGINX.
The following table shows which proxies are used and in which Pod they run.

| Usage  | Proxy | Pod | Namespace               | Description |
| ------------- |:------------- |:------------- |:------------------------|:-------------
| System ingress | NGINX | `ingress-controller-ingress-nginx-controller-*` | `ingress-nginx`         | Provides external access to Verrazzano system components.
| Verrazzano authentication proxy | NGINX | `verrazzano-authproxy-*` | `verrazzano-system`     | Verrazzano authentication proxy server for Kubernetes API and Single Sign-On (SSO).
| Application ingress | Envoy | `istio-ingressgateway-*` | `istio-system`          | Provides external access to Verrazzano applications.
| Application egress | Envoy | `istio-egressgateway-*` | `istio-system`          | Provides control of application egress traffic.
| Istio mesh sidecar | Envoy  | `ingress-controller-ingress-nginx-controller-*` | `ingress-nginx`         | Ingress NGINX Controller in the Istio mesh.
| Istio mesh sidecar | Envoy  | `ingress-controller-ingress-nginx-defaultbackend-*` | `ingress-nginx`         | NGINX default backend in the Istio mesh.
| Istio mesh sidecar | Envoy  | `fluentd-*` | `verrazzano-system`     | Fluentd in the Istio mesh.
| Istio mesh sidecar | Envoy  | `keycloak-*` | `keycloak`              | Keycloak in the Istio mesh.
| Istio mesh sidecar | Envoy  | `mysql-*` | `keycloak`              | MySQL used by Keycloak in the Istio mesh.
| Istio mesh sidecar | Envoy | `verrazzano-api-*` | `verrazzano-system`     | Verrazzano API in the Istio mesh.
| Istio mesh sidecar | Envoy | `verrazzano-console-*` | `verrazzano-system`     | Verrazzano Console in the Istio mesh.
| Istio mesh sidecar | Envoy  | `vmi-system-grafana-*` | `verrazzano-system`     | Grafana in the Istio mesh.
| Istio mesh sidecar | Envoy  | `weblogic-operator-*` | `verrazzano-system`     | WebLogic Kubernetes Operator in the Istio mesh.
| Istio mesh sidecar | Envoy  | `prometheus-prometheus-operator-kube-p-prometheus-*` | `verrazzano-monitoring` | Prometheus in the Istio mesh.

## Multicluster
Some Verrazzano components send traffic between Kubernetes clusters. Those components are the Verrazzano agent,
Verrazzano authentication proxy, and Prometheus.

### Multicluster egress
The following table shows Verrazzano system components that initiate requests between the admin and managed clusters.
All of these requests go through the Ingress NGINX Controller on the respective destination cluster.

Traffic on port 443 needs to be allowed in both directions, from managed clusters to the admin cluster, and from
the admin cluster to managed clusters. Additionally, if Rancher is not enabled on the admin cluster, then managed
clusters will also need access to the admin cluster's Kubernetes API server port (typically, this is port 6443).

| Source Cluster | Source Component | Destination Cluster | Destination Component | Description
| ------------- |:------------- |:------------- |:------------- |:-------------
| Admin | Prometheus | Managed | Prometheus | Scrapes metrics on managed clusters.
| Admin | argoCD | Managed | Rancher Proxy | Argo CD connects to the Rancher proxy for creating resources required for the Argo CD managed cluster registration.
| Admin | Verrazzano Console | Managed | Verrazzano Authentication Proxy | Admin cluster proxy sends Kubernetes API requests to managed cluster proxy.
| Admin | Verrazzano Cluster Operator | Managed | Rancher Proxy | Admin cluster sends registration updates to managed cluster, and retrieves managed cluster CA certificate.
| Managed | Fluentd | Admin | OpenSearch | Fluentd sends logs to OpenSearch.
| Managed | Rancher Agent | Admin | Rancher | Rancher Agent sends requests Rancher.
| Managed | Verrazzano Authentication Proxy | Admin | Keycloak | Proxy sends requests to Keycloak.
| Managed | Verrazzano Agent | Admin | Rancher Proxy or Kubernetes API server | Managed cluster agent, in the application operator, sends requests to the Rancher proxy if Rancher is enabled, or to the admin cluster Kubernetes API server.

### Verrazzano agent
In the multicluster topology, the Verrazzano platform operator has an agent thread running on the managed cluster
that sends requests to the Kubernetes API server on the admin cluster. The URL for the admin cluster Kubernetes
API server is registered on the managed cluster by the user.

### Verrazzano authentication proxy
In a multicluster topology, the Verrazzano authentication proxy runs on both the admin and managed clusters.
On the admin cluster, the authentication proxy connects to in-cluster Keycloak, using the Keycloak Service.
On the managed cluster, the authentication proxy connects to Keycloak on the admin cluster through the NGINX Ingress
Controller running on the admin cluster.

For Single Sign-On (SSO), the authentication proxy also needs to send requests to Keycloak, either in-cluster or through the cluster ingress. When a
request comes into the authentication proxy without an authentication header, the proxy sends a request to Keycloak
through the Ingress NGINX Controller, so the request exits the cluster.  Otherwise, if the authentication proxy is on the admin cluster, then the request is
sent directly to Keycloak within the cluster.  If the authentication proxy is on the managed
cluster, then it must send requests to Keycloak on the admin cluster.

### Prometheus
A single Prometheus service in the cluster, scrapes metrics from Pods in system components and applications.
It also scrapes Pods in the Istio mesh using HTTPS, and outside the mesh using HTTP. In the multicluster case,
Prometheus on the admin cluster, scrapes metrics from Prometheus on the managed cluster, through
the Ingress NGINX Controller on the managed cluster.
