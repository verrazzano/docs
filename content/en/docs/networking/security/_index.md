---
title: "Network Security"
description: ""
weight: 2
draft: false
---

Verrazzano manages and secures network traffic between Verrazzano system components and deployed applications.
Verrazzano does not manage or secure traffic for the Kubernetes cluster itself, or for
non-Verrazzano services or applications running in the cluster. Traffic is secured at two levels in the network stack:

- ISO Layer 3/4: Using NetworkPolicies to control IP access to Pods.
- ISO Layer 6: Using TLS and mutual TLS authentication (mTLS) to provide authentication, confidentiality,
and integrity for connections within the cluster and for external connections.

## NetworkPolicies
By default, all Pods in a Kubernetes cluster have network access to all other Pods in the cluster.
Kubernetes has a NetworkPolicy resource that provides network level 3 and 4 security for Pods,
restricting both ingress and egress IP traffic for a set of Pods in a namespace.  Verrazzano configures all
system components with NetworkPolicies to control ingress.  Egress is not restricted.

**NOTE**: A NetworkPolicy resource needs a NetworkPolicy controller to implement the policy, otherwise the
policy has no effect.  You must install a Kubernetes Container Network Interface (CNI) plug-in that provides a NetworkPolicy controller,
such as Calico, before installing Verrazzano, or else the policies are ignored.

### NetworkPolicies for system components
Verrazzano installs a set of NetworkPolicies for system components to control ingress into the Pods.
A policy is scoped to a namespace and uses selectors to specify the Pods that the policy applies to, along
with the ingress and egress rules.  For example, the following policy applies to the Verrazzano API Pod in the
`verrazzano-system` namespace.  This policy allows network traffic from NGINX Ingress Controller on
port 8775 and from Prometheus on port 15090.  No other Pods can reach those ports or any other ports of the
Verrazzano API Pod.  Notice that namespace selectors need to be used; the NetworkPolicy resource does not support
specifying the namespace name.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
...
spec:
  PodSelector:
    matchLabels:
      app: verrazzano-api
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: ingress-nginx
      PodSelector:
        matchLabels:
          app.kubernetes.io/instance: ingress-controller
    ports:
    - port: 8775
      protocol: TCP
  - from:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-system
      PodSelector:
        matchLabels:
          app: system-prometheus
    ports:
    - port: 15090
      protocol: TCP
```

</div>
{{< /clipboard >}}

The following table shows all of the ingresses that allow network traffic into system components.
The ports shown are Pod ports, which is what NetworkPolicies require.


| Component  | Pod Port           | From  | Description |
| ------------- |:------------- |:------------- |:----- |:-------------:|
| Argo CD | 443 | NGINX Ingress  | 	Access from external client
| Argo CD | 8080 | Argo CD Server, Internal  | 	Argo CD Server data port
| cert-manager| 9402 | Prometheus | Prometheus scraping
| Coherence Operator | 9443 | Prometheus | Webhook entrypoint
| Istio control plane | 15012 | Envoy | Envoy access to `istiod`
| Istio control plane | 15014 | Prometheus | Prometheus scraping.
| Istio control plane | 15017 | Kubernetes API Server  | Webhook entrypoint
| Istio egress gateway | 8443 | Mesh services | Application egress
| Istio egress gateway| 15090 | Prometheus | Prometheus scraping
| Istio ingress gateway | 8443 | External | Application ingress
| Istio ingress gateway| 15090 | Prometheus | Prometheus scraping
| Keycloak| 8080 | NGINX Ingress | Access from external client
| Keycloak| 15090 | Prometheus | Prometheus scraping
| MySql| 15090 | Prometheus | Prometheus scraping
| MySql| 3306 | Keycloak | Keycloak datastore
| Node exporter| 9100 | Prometheus | Prometheus scraping
| OpenSearch | 8775 | Fluentd | Access from Fluentd
| OpenSearch | 9200 | OpenSearch Dashboards, Internal | OpenSearch data port
| OpenSearch | 9300 | Internal | OpenSearch cluster port  
| OpenSearch | 15090 | Prometheus | Envoy metrics scraping
| OpenSearch | 8775 | NGINX Ingress | Access from external client
| Prometheus | 8775 | NGINX Ingress | Access from external client
| Prometheus | 9090 | Grafana | Access for Grafana console
| Rancher | 80 | NGINX Ingress | Access from external client
| Rancher | 9443 |  Kubernetes API Server  | Webhook entrypoint
| Verrazzano Application Operator | 9443 | Kubernetes API Server  | Webhook entrypoint
| Verrazzano Authentication Proxy | 8775 | NGINX Ingress | Access from external client
| Verrazzano Authentication Proxy | 15090 | Prometheus | Prometheus scraping
| Verrazzano Console | 8000 | NGINX Ingress |  Access from external client
| Verrazzano Console | 15090 | Prometheus | Prometheus scraping
| Verrazzano Platform Operator | 9443 | Kubernetes API Server  | Webhook entrypoint

### NetworkPolicies for applications
By default, applications do not have NetworkPolicies that restrict ingress into the application or egress from it.
You can configure them for the application namespaces using the NetworkPolicy section of a Verrazzano project.

{{< alert title="NOTE" color="primary" >}}
Verrazzano requires specific ingress to and egress from application pods. If you add a NetworkPolicy for your application namespace or pods,
you must add an additional policy to ensure that Verrazzano still has the required access it needs. The ingress policy is needed only if you restrict ingress.
Likewise, the egress policy is needed only if you restrict egress. The following are the ingress and egress NetworkPolicies:
<details>
<summary>Ingress NetworkPolicies</summary>

```
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: istio-system
      podSelector:
        matchLabels:
          app: istiod
  - from:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: istio-system
      podSelector:
        matchLabels:
          app: istio-ingressgateway
  - from:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-system
      podSelector:
        matchLabels:
          app: system-prometheus
  - from:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-system
      podSelector:
        matchLabels:
          app: coherence-operator
  - from:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-system
      podSelector:
        matchLabels:
          app: weblogic-operator
```
</details>

<details>
<summary>Egress NetworkPolicies</summary>

```
  egress:
  - ports:
    - port: 15012
      protocol: TCP
    to:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: istio-system
      podSelector:
        matchLabels:
          app: istiod
  - to:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: istio-system
      podSelector:
        matchLabels:
          app: istio-egressgateway
  - ports:
    - port: 53
      protocol: TCP
    - port: 53
      protocol: UDP
    to:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: kube-system
  - ports:
    - port: 8000
      protocol: TCP
    to:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-system
      podSelector:
        matchLabels:
          app: coherence-operator
```
</details>
{{< /alert >}}

### NetworkPolicies for Envoy sidecar proxies
As mentioned, Envoy sidecar proxies run in both system component pods and application pods.  Each proxy sends requests
to the Istio control plane pod, `istiod`, for a variety of reasons. During installation, Verrazzano creates a NetworkPolicy
named `istiod-access` in the `istio-system` namespace to give ingress to system component and application sidecar proxies.

## Mutual TLS authentication (mTLS)
Istio can be enabled to use mTLS between services in the mesh, and also between the Istio gateways and Envoy sidecar proxies.
There are various options to customize mTLS usage, for example it can be disabled on a per-port level.  The Istio
control plane, Istiod, is a CA and provides key and certificate rotation for the Envoy proxies, both gateways and sidecars.

Verrazzano configures Istio to have strict mTLS for the mesh.  All components and applications put into the mesh
will use mTLS, with the exception of Coherence clusters, which are not in the mesh. Also, all traffic between the Istio
ingress gateway and mesh sidecars use mTLS, and the same is true between the proxy sidecars and the egress gateway.   

Verrazzano sets up mTLS during installation with the PeerAuthentication resource as follows:
{{< clipboard >}}
<div class="highlight">

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

</div>
{{< /clipboard >}}

## TLS
TLS is used by external clients to access the cluster, both through the NGINX Ingress Controller and the Istio ingress gateway.
The certificate used by these TLS connections vary; see [Verrazzano security]({{< relref "/docs/security/_index.md" >}}) for details.
All TLS connections are terminated at the ingress proxy. Traffic between the two proxies and the internal cluster Pods
always uses mTLS, because those Pods are all in the Istio mesh.

## Istio mesh
Istio provides extensive security protection for both authentication and authorization, as described in
[Istio Security](HTTPS://istio.io/latest/docs/concepts/security). Access control and mTLS are two security
features that Verrazzano configures.  These security features are available in the context of a service mesh.

A service mesh is an infrastructure layer that provides certain capabilities like security, observability, load balancing,
and such, for services.  Istio defines a service mesh [here](HTTPS://istio.io/latest/about/service-mesh/).
In the context of Istio on Kubernetes, a service in the mesh is a Kubernetes Service. Consider the Bob's Books example application, which
has several OAM Components defined.  At runtime, there is a Kubernetes Service for each component, and each Service is
in the mesh, with one or more Pods associated with the service.  All services in the mesh have an Envoy proxy in
front of their Pods, intercepting network traffic to and from the Pod.  In Kubernetes, that proxy happens to be a sidecar
running in each Pod.  

There are various ways to put a service in the mesh. Verrazzano uses the namespace label, `istio-injection: enabled`,
to designate that all Pods in a given namespace are in the mesh.  When a Pod is created in that namespace, the Istio control
plane mutating webhook, changes the Pod spec to add the Envoy proxy sidecar container, causing the Pod to be in the mesh.

### Disabling sidecar injection
In certain cases, Verrazzano needs to disable sidecar injection for specific Pods in a namespace.  This is done in two ways:
first, during installation, Verrazzano modifies the `istio-sidecar-injector` ConfigMap using a Helm override file for the Istio
chart.  This excludes several components from the mesh, such as the Verrazzano application operator.  Second, certain Pods, such
as Coherence Pods, are labeled at runtime with `sidecar.istio.io/inject="false"` to exclude them from the mesh.  

## Components in the mesh
The following Verrazzano components are in the mesh and use mTLS for all service to service communication.
- Argo CD
- Fluentd
- Grafana
- Kiali
- Keycloak
- MySQL
- NGINX Ingress Controller
- OpenSearch
- OpenSearch Dashboards
- Prometheus
- Verrazzano Authentication Proxy
- Verrazzano Console
- WebLogic Kubernetes Operator

Some of these components, have mesh-related details that are worth noting, as described in the following sections.

### NGINX
The NGINX Ingress Controller listens for HTTPS traffic, and provides ingress into the cluster.  NGINX is
configured to do TLS termination of client connections.  All traffic from NGINX to the mesh services
use mTLS, which means that traffic is fully encrypted from the client to the target back-end services.

### Keycloak and MySQL
Keycloak and MySQL are also in the mesh and use mTLS for network traffic.  Because all of the components that use
Keycloak are in the mesh, there is end to end mTLS security for all identity management handled by Keycloak.  The following components
access Keycloak:
- Verrazzano Authentication Proxy
- Verrazzano Console
- OpenSearch
- Prometheus
- Grafana
- Kiali
- OpenSearch Dashboards

### Prometheus
Although Prometheus is in the mesh, it is configured to use the Envoy sidecar and mTLS only when communicating with
Keycloak.  All the traffic related to scraping metrics, bypasses the sidecar proxy, doesn't use
the service IP address, but rather connects to the scrape target using the Pod IP address.  If the scrape target is in the mesh,
then HTTPS is used; otherwise, HTTP is used.  For Verrazzano multicluster, Prometheus also connects from the admin cluster
to the Prometheus server in the managed cluster by using the managed cluster NGINX Ingress, using HTTPS.  Prometheus
is in the managed cluster and never establishes connections to targets outside the cluster.

Because Prometheus is in the mesh, additional configuration is done to allow the Envoy sidecar to be bypassed when scraping Pods.
This is done with the Prometheus Pod annotation `traffic.sidecar.istio.io/includeOutboundIPRanges: <keycloak-service-ip>`.  This
causes traffic bound for Keycloak to go through the Envoy sidecar, and all other traffic to bypass the sidecar.

### WebLogic Kubernetes Operator
When the WebLogic Kubernetes Operator creates a domain, it needs to communicate with the Pods in the domain. Verrazzano puts the
operator in the mesh so that it can communicate with the domain Pods using mTLS.  As a result, the WebLogic
domain must be created in the mesh.

## Applications in the mesh
Before you create a Verrazzano application, you should decide if it should be in the mesh.  You control sidecar injection,
for example, mesh inclusion, by labeling the application namespace with `istio-injection=enabled` or `istio-injection=disabled`.
By default, applications will not be put in the mesh if that label is missing.  If your application uses a Verrazzano
project, then Verrazzano will label the namespaces in the project to enable injection. If the application is in the mesh,
then mTLS will be used.  You can change the PeerAuthentication mTLS mode as desired if you don't want strict mTLS.
Also, if you need to add mTLS port exceptions, you can do this with DestinationRules or by creating another PeerAuthentication
resource in the application namespace.  Consult the Istio documentation for more information.

### WebLogic
When the WebLogic Kubernetes Operator creates a domain, it needs to communicate with the Pods in the domain. Verrazzano puts the operator
in the mesh so that it can communicate with the domain Pods using mTLS.  Because of that, the WebLogic domain must be created in the mesh.
Also, because mTLS is used, do not configure WebLogic to use TLS.  If you want to use a custom certificate for your application,
you can specify that in the ApplicationConfiguration, but that TLS connection will be terminated at the Istio ingress gateway, which
you configure using a Verrazzano IngressTrait.

### Coherence
Coherence clusters are represented by the Coherence resource, and are not in the mesh.  When Verrazzano creates a Coherence
cluster in a namespace that is annotated to do sidecar injection, it disables injection of the Coherence resource using the
`sidecar.istio.io/inject="false"` label shown previously.  Furthermore, Verrazzano will create a DestinationRule in the application
namespace to disable mTLS for the Coherence extend port `9000`.  This allows a service in the mesh to call the Coherence
extend proxy.  For an example, see [Bobs Books]( {{< release_source_url path=examples/bobs-books >}} ).

Here is an example of a DestinationRule created for the Bob's Books application which includes a Coherence cluster.
{{< clipboard >}}
<div class="highlight">

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

</div>
{{< /clipboard >}}

## Istio access control
Istio lets you control access to your workload in the mesh using the AuthorizationPolicy resource. This lets you
control which services or Pods can access your workloads.  Some of these options require mTLS; for more information, see
[Authorization Policy](HTTPS://istio.io/latest/docs/reference/config/security/authorization-policy/).

Verrazzano always creates AuthorizationPolicies for applications but never for system components.  During application deployment,
Verrazzano creates the policy in the application namespace and configures it to allow access from the following:

- Other Pods in the application
- Istio ingress gateway
- Prometheus scraper

This prevents other Pods in the cluster from gaining network access to the application Pods.
Istio uses a service identity to determine the identity of the request's origin; for Kubernetes
this identity is a service account.  Verrazzano creates a per-application AuthorizationPolicy as follows:
{{< clipboard >}}
<div class="highlight">

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

</div>
{{< /clipboard >}}

## WebLogic domain access
For WebLogic applications, the WebLogic Kubernetes Operator must have access to the domain Pods for two reasons.
First, it must access the domain servers to get health status; second, it must inject configuration into
the Monitoring Exporter sidecar running in the domain server Pods. When a WebLogic domain is created,
Verrazzano adds an additional source, `cluster.local/ns/verrazzano-system/sa/weblogic-operator-sa` to
the `principals` section to permit that access.
