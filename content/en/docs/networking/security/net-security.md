---
title: "Network Security"
linkTitle: "Network Security"
description: "Verrazzano Network Security"
weight: 3
draft: true
---
## Overview
Verrazzano manages and secures network traffic to, from, and between Verrazzano system components and deployed applications. 
We do not manage or secure traffic for the Kubernetes cluster itself, or for non-Verrazzano services or applications 
running in the cluster. Traffic is secured at two levels in the network stack:

- ISO Layer 3/4: Using NetworkPolicy to control IP access to pods
- ISO Layer 6: Using TLS and mTLS to provide authentication, confidentiality, 
and integrity for connections within the cluster, and for external connections.

## NetworkPolicies
By default, all pods in a Kubernetes cluster have network access all other pods over the network. 
Kubernetes has a NetworkPolicy resource that provides network level 3 and 4 security for pods, 
restricting both ingress and egress IP traffic for a set of pods in a namespace.  Verrazzano configures all
system components with NetworkPolicies to control ingress.  Egress is not restricted. By default, 
applications do not have NetworkPolicies, but you can configure them using a Verrazzano project.

**NOTE:** A NetworkPolicy resource needs a NetworkPolicy controller to implement the policy, otherwise the 
policy has no effect.  A Kubernetes CNI plugin that provides a NetworkPolicy controller, such as Calico, must be installed by 
the user before installing Verrazzano.  

### NetworkPolicies for system components
Verrazzano installs a set of NetworkPolicies for system components to control ingress into the pods.
A policy is scoped to a namespace and uses selectors to specify the pods that the policy applies to, along
with the ingress and egress rules.  For example, the following policy applies to the Verrazzano API pod in the 
`verrazzano-system` namespace.  This policy allows network traffic from NGINX Ingress controller on
port 8775, and from Prometheus on port 15090.  No other pods can reach those ports or any other ports of the
Verrazzano API pod.
```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
...
spec:
  podSelector:
    matchLabels:
      app: verrazzano-api
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: ingress-nginx
      podSelector:
        matchLabels:
          app.kubernetes.io/instance: ingress-controller
    ports:
    - port: 8775
      protocol: TCP
  - from:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-system
      podSelector:
        matchLabels:
          app: system-prometheus
    ports:
    - port: 15090
      protocol: TCP
```

The following table shows all of the ingresses allowed into system components.
The ports shown are pod ports, which is what NetworkPolices require.


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

## Istio Mesh
Istio provides extensive security protection for both authentication and authorization as described here 
[Istio Security](https://istio.io/latest/docs/concepts/security). Access control and mTLS are two security 
features that Verrazzano configures.  These security features are available in the context of a service mesh.

A service mesh is an infrastructure layer that provides certain capabilities like security, observabilty, load balancing,
etc. for services.  Istio defines a service mesh here [Istio Service Mesh](https://istio.io/latest/about/service-mesh/).
What does it mean for a service to be in the mesh?  Basically, it means that there is an Envoy proxy in front of every 
service intercepting inbound and outbound network traffic for that service.  In Kubernetes, that proxy happens to be a sidecar 
running in the all the pods used by the service. There are various ways to put a service in the mesh, Verrazzano uses the
namespace label, `istio-injection: enabled`,  to designate that all pods in a given namespace are in mesh.  When a pod is 
created in that namespace, an Istio control plane mutating webhook changes the pod spec to add the Envoy proxy sidecar container,
causing the pod to be in the mesh. 

#### Disabling sidecar injection
In certain cases, Verrazzano needs to disable sidecar injection for specific pods in a namespace.  This is done in two ways:
first, during installation, Verrazzano modifies the `istio-sidecar-injector` configmap using a helm override file for the Istio
chart.  This excludes several components from the mesh, such as the Verrazzano Application Operator.  Second, certain pods, such 
as Coherence pods, are labeled at runtime with `sidecar.istio.io/inject="false"` to exclude them from the mesh.  

## mTLS
Istio can be enabled to use mTLS between services in the mesh, and also between the gateways and sidecar proxies.
There are various options to customize mTLS usage, for example it can be disabled on a per port level.  The Istio 
control plane, istiod, is a CA and provides key and certificate rotation for the Envoy proxies, both gateways and sidecar. 

Verrazzano configures Istio to have strict mTLS for the mesh.  All components and applications put into the mesh
will use mTLS, with the exception of Coherence clusters which are not in the mesh.  All traffic between the Istio
ingress gateway and mesh sidecars also use mTLS, and the same is true between the proxy sidecars and the engress gateway.
Verrazzano sets up mTLS during installation with the PeerAuthorization resource as follows:
```
apiVersion: v1
items:
- apiVersion: security.istio.io/v1beta1
  kind: PeerAuthentication
  ...
  spec:
    mtls:
      mode: STRICT
```

## Components in the Mesh
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

### Coherence
Coherence clusters are represented by the `Coherence` resource, and are not in the mesh.  When Verrazzano creates a Coherence
cluster in a namespace that is annotated to do sidecar injection, then it disables injection the Coherence resource using the
`sidecar.istio.io/inject="false"` label shown previously.  Furthermore, Verrazzano will create a DestinationRule in the application
namespace to disable mTLS for the the Coherence extend port `9000`.  This allows a service in the mesh to call the Coherence 
extend proxy.  See bob's books for an example at [bobs-books](https://github.com/verrazzano/verrazzano/blob/master/examples/bobs-books).
Here is an example of DestinationRule created for the bob's books application which is in the mesh and includes a Coherence cluster.
```
API Version:  networking.istio.io/v1beta1
Kind:         DestinationRule
...
Spec:
  Host:  *.bobs-books.svc.cluster.local
  Traffic Policy:
    Port Level Settings:
      Port:
        Number:  9000
      Tls:
    Tls:
      Mode:  ISTIO_MUTUAL
```


## Applications in the Mesh
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


## Istio Access Control
Istio allows you to control access to your workload in the mesh, using the `AuthorizationPolicy` resource. This allows you
to control what services or pods can access your workloads.  Some of these options require mTLS, see 
[Authorization Policy](https://istio.io/latest/docs/reference/config/security/authorization-policy/) for more information.

Verrazzano creates AuthorizationPolicies for applications, never for system components.  During application deployment, 
Verrazzano creates the policy in the application namespace and configures it to allow access traffic from the following:

- Other pods in the namespace
- Prometheus scraper
- Istio ingress gateway

This prevents any other pods in the cluster from gaining network access to the application pods.  
Istio uses a service identity to determine the identity of the request's origin, for Kubernetes, 
this identity is a service account.  Verrazzano configures this as shown below:
```
AuthorizationPolicy
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
...
spec:
rules:
- from:
- source:
principals:
- cluster.local/ns/sales/sa/greeter
- cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account
- cluster.local/ns/verrazzano-system/sa/verrazzano-monitoring-operator
```

### WebLogic domain access
For WebLogic applications, the WebLogic operator must have access to the domain pods for two reasons.
First it must access the domain servers to get health status, second it must inject configuration into
the Monitoring Exporter sidecar running in the domain server pods. When a WebLogic domain is created, 
adds an additional source in the principals section to permit that access. 


