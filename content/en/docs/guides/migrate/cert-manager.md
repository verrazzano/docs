---
title: "Cert-Manager"
linkTitle: "Cert-Manager"
description: ""
weight: 1
draft: false
---
## How Verrazzano Installs Cert-Manager

### Components
Verrazzano supports the installation of [Cert-Manager](https://cert-manager.io/), or using a customer-managed Cert-Manager instance.  
Depending on the configuration, Verrazzano will install the following components:

- Cert-Manager
- The Verrazzano [cert-manager-webhook-oci](https://github.com/verrazzano/cert-manager-webhook-oci) webhook for signing certificates using Let's Encrypt.

Verrazzano also configures a Cert-Manager [ClusterIssuer](https://cert-manager.io/docs/configuration/) to sign leaf certificates for all externally accessible endpoints.

### Verrazzano Chart Overrides

#### Images
Verrazzano overrides image registries, repositories, and image tags to install Oracle built-from-source images. Registry overrides are also applied when installing Verrazzano from a private registry (for example, in a disconnected network environment).

#### Pod and Container Security
Verrazzano overrides certain pod and container security settings enhance the security of applications running in the cluster. For example, privilege escalation is disabled in pods to mitigate escalation attacks in a cluster.

#### ClusterResourceNamespace
Verrazzano sets the location for `ClusterIssuer` secrets used by Cert-Manager called the [clusterResourceNamespace](https://cert-manager.io/docs/configuration/#cluster-resource-namespace).  This is the same namespace where Cert-Manager is installed by default but can be overridden when a custom Certificate Authority is used.

#### Other
Verrazzano overrides chart values for various other settings, including specifying memory and storage and requests, namespace, and so on.

## Migration Steps
Follow these steps to install (or upgrade) and configure monitoring components. The result should be a cluster running a Cert-Manager instance with a `ClusterIssuer` that achieves near-equivalent functionality compared to the Verrazzano-installed Cert-Manager stack.

### Installing Cert-Manager
**TBD**, will be installed as a first-class CNE module and not from the app catalog

#### Override Recipes

##### Installing from a Private Registry
**TBD** - need OCNE module private registry example

##### Configuring Pod and Container Security
Override pod and container security default settings to limit actions that pods and containers can perform in the cluster. These settings allow pods and containers to perform only operations that are needed for them to operate successfully, and mitigate security vulnerabilities, such as privilege escalation.

For example, apply the following overrides when installing the Cert-Manager module in an OCNE 2.0 cluster to use security settings similar to those used by Verrazzano 1.6:

{{< clipboard >}}
<div class="highlight">

```
securityContext:
  runAsNonRoot: true
  seccompProfile:
    type: RuntimeDefault

containerSecurityContext:
  allowPrivilegeEscalation: false
  privileged: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 65534
  runAsGroup: 65534
  capabilities:
   drop:
   - ALL

cainjector:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containerSecurityContext:
    allowPrivilegeEscalation: false
    privileged: false
    readOnlyRootFilesystem: true
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
    capabilities:
      drop:
        - ALL

webhook:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containerSecurityContext:
    allowPrivilegeEscalation: false
    privileged: false
    readOnlyRootFilesystem: true
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
    capabilities:
      drop:
        - ALL
  ```
  </div>
  {{< /clipboard >}}

##### Configuring Storage and Resource Limits and Requests

Specify overrides to change the default resource (storage, cpu, memory, etc.) requests and limits.

For example, to apply a custom resource requests for Cert-Manager pods create the following overrides file and apply it when installing the module:

{{< clipboard >}}
<div class="highlight">

```
resources:
  requests:
    cpu: 100m
    memory: 256Mi
```
</div>
{{< /clipboard >}}

### Installing the OCI DNS Webhook Solver

If you intend to use Cert-Manager with Let's Encrypt and OCI DNS you will need to install the `cert-manager-webhook-oci`  module from the OCNE application catalog.
The webhook solver is installed using the OCNE Application Catalog. The first step is to add the Application Catalog Helm repository to the cluster.

{{< clipboard >}}
<div class="highlight">

```
$ helm repo add ocne-app-catalog https://ocne-app-catalog-url
$ helm repo update
```
</div>
{{< /clipboard >}}

Next install the Helm chart for the webhook:
{{< clipboard >}}
<div class="highlight">

```
$ helm install cert-manager-webhook-oci ocne-app-catalog/cert-manager-webhook-oci-1.0.0 -n cert-manager
```
</div>
{{< /clipboard >}}

In the previous example, we install it into the default `cert-manager` namespace, however, this is not required.

#### Helm Override Recipes

##### Changing the Cert-Manager Locations

If Cert-Manager is installed in a non-default namespace (something other than `cert-manager`), then this will need to be provided to the webhook install as Helm overrides:
{{< clipboard >}}
<div class="highlight">

```
$ helm install cert-manager-webhook-oci ocne-app-catalog/cert-manager-webhook-oci-1.0.0 --set certManager.namespace=my-cm --set certManager.clusterResourceNamespace=my-cluster-resources
```
</div>
{{< /clipboard >}}

##### Installing from a Private Registry

In order to install using a private registry (for example, in a disconnected environment), you must override Helm values to change the webhook image path.

For example, to install `cert-manager-webhook-oci` from a private registry at `myprivreg.com/verrazzano/cert-manager-webhook-oci`, create an overrides file with the following content and specify it using the `-f` option when running `helm upgrade --install`:
{{< clipboard >}}
<div class="highlight">

```
image:
  repository: myprivreg.com/verrazzano/cert-manager-webhook-oci
```
</div>
{{< /clipboard >}}

##### Configuring Pod and Container Security

Override pod and container security default settings to limit actions that pods and containers can perform in the cluster. These settings allow pods and containers to only perform operations that are needed for them to operate successfully, and mitigate security vulnerabilities, such as privilege escalation.

For example, to apply security settings similar to those used by Verrazzano, in OCNE 2.0 use the following overrides by using the `-f` option when running `helm upgrade --install` on the `cert-manager-wehbook-oci` chart:
{{< clipboard >}}
<div class="highlight">

```
allowPrivilegeEscalation: false
privileged: false
runAsNonRoot: true
runAsUser: 1000
runAsGroup: 999
capabilities:
  drop:
    - ALL

seccompProfile:
  type: RuntimeDefault
```
</div>
{{< /clipboard >}}

##### Configuring Storage and Resource Limits and Requests

Specify overrides to change the default resource (storage, cpu, memory, etc.) requests and limits.
For example, to update resource requests for the webhook, create the following overrides file and provide the file using the `-f` option when running `helm upgrade --install`:
{{< clipboard >}}
<div class="highlight">

```
resources:
  requests:
    memory: 400Mi
    cpu: 400m
```
</div>
{{< /clipboard >}}

### Installing Network Policies
NetworkPolicies allow you to specify how a pod is allowed to communicate with various network entities in a cluster. NetworkPolicies increase the security posture of the cluster by limiting network traffic and preventing unwanted network communication. NetworkPolicy resources affect layer 4 connections (TCP, UDP, and optionally SCTP). The cluster must be running a Container Network Interface (CNI) plug-in that enforces NetworkPolicies.

For example, if Prometheus is installed in the target cluster and you wish to limit access to Cert-Manager only from Prometheus for metrics scraping, you can apply a network policy to enforce this.

If the Prometheus instance is installed using the Prometheus operator in the namespace monitoring with the label `myapp.io/namespace=monitoring`, then the network policy can be applied as follows:
{{< clipboard >}}
<div class="highlight">

```
kubectl apply -n cert-manager -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cert-manager
  namespace: cert-manager
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          myapp.io/namespace: monitoring
      podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
    ports:
    - port: 9402
      protocol: TCP
  podSelector:
    matchLabels:
      app: cert-manager
  policyTypes:
  - Ingress
EOF
```
</div>
{{< /clipboard >}}

This will restrict ingress to be allowed only to pods in the `cert-manager` namespace with the `app: cert-manager` label on TCP port 9402 from Prometheus pods the `monitoring`  namespace.

### Usage

The steps in this section describe examples of how to create Cert-Manager `ClusterIssuers` that are functionally equivalent to those employed by Verrazzano and use them to secure endpoints.

#### Self-Signed `ClusterIssuer`

To create a self-signed `ClusterIssuer` similar to those used by Verrazzano, you must:

1. Create a Cert-Manager self-signed `Issuer` or `ClusterIssuer`.
1. Create a self-signed `root` Certificate using the issuer from Step 1.
1. Create a `ClusterIssuer` using the TLS secret created by the `root` Certificate object from Step 2.

The `ClusterIssuer` created in Step 3 can then be used to sign leaf Certificate requests.

##### Creating a Self-Signed Root Certificate

When using self-signed certificates, you need to start with a root CA. The Cert-Manager [SelfSigned](https://cert-manager.io/docs/configuration/selfsigned/) issuer can be used to set this up, as described in the following sequence:

1. Create a [SelfSigned](https://cert-manager.io/docs/configuration/selfsigned/) issuer in the Cert-Manager namespace needed to create the root CA; if you are using a `ClusterIssuer`, then you must use the [cluster resource namespace](https://cert-manager.io/docs/configuration/#cluster-resource-namespace) (typically the namespace where cert-manager  is installed).
1. Create a Certificate that refers to the issuer; if a namespace-scoped `Issuer` is used the `Certificate` must be created in the same namespace as the `Issuer`.

The `cert-manager` controller will then create the secret referenced in the `Certificate` object (Step 2) that contains the root certificate and private key.

For example, to create a `SelfSigned` root CA using a `ClusterIssuer`:

**Root ClusterIssuer**
{{< clipboard >}}
<div class="highlight">

```
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: my-root-issuer
spec:
  selfSigned: {}
```
</div>
{{< /clipboard >}}

**Example: Root Issuer Creation**
{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: my-root-issuer
spec:
  selfSigned: {}
EOF

$ kubectl get clusterissuers.cert-manager.io -o yaml my-root-issuer
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"cert-manager.io/v1","kind":"ClusterIssuer","metadata":{"annotations":{},"name":"my-root-issuer"},"spec":{"selfSigned":{}}}
  creationTimestamp: "2024-01-08T16:49:15Z"
  generation: 1
  name: my-root-issuer
  resourceVersion: "1218737"
  uid: e3d3b5b3-58fe-4e22-82e4-ca0800c32a4e
spec:
  selfSigned: {}
status:
  conditions:
  - lastTransitionTime: "2024-01-08T16:49:15Z"
    observedGeneration: 1
    reason: IsReady
    status: "True"
    type: Ready
```
</div>
{{< /clipboard >}}

Then create a `Certificate` to be signed by `my-root-issuer` with the TLS secret, `my-root-ca-tls`.  Because we are using a `ClusterIssuer,` the `Certificate` object should be created in the `clusterResourceNamespace`, which by default is the `cert-manager` namespace:

**Root Certificate**
{{< clipboard >}}
<div class="highlight">

```
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-root-ca
  namespace: cert-manager
spec:
  isCA: true
  commonName: my-root-ca
  secretName: my-root-ca-tls
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: my-root-issuer
    kind: ClusterIssuer
    group: cert-manager.io
```
</div>
{{< /clipboard >}}

**Example: Create self-signed root Certificate**
{{< clipboard >}}
<div class="highlight">

```
# Create the self-signed root certificate

$ kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-root-ca
  namespace: cert-manager
spec:
  isCA: true
  commonName: my-root-ca
  secretName: my-root-ca-tls
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: my-root-issuer
    kind: ClusterIssuer
    group: cert-manager.io
EOF
certificate.cert-manager.io/my-root-ca created

# Display the certificate object

$ kubectl get certificate -o yaml -n cert-manager my-root-ca
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"cert-manager.io/v1","kind":"Certificate","metadata":{"annotations":{},"name":"my-root-ca","namespace":"cert-manager"},"spec":{"commonName":"my-root-ca","isCA":true,"issuerRef":{"group":"cert-manager.io","kind":"ClusterIssuer","name":"my-root-issuer"},"privateKey":{"algorithm":"ECDSA","size":256},"secretName":"my-root-ca-tls"}}
  creationTimestamp: "2024-01-08T16:53:47Z"
  generation: 1
  name: my-root-ca
  namespace: cert-manager
  resourceVersion: "1219862"
  uid: 1c1fbea4-38c7-494c-8794-4354d3306ed3
spec:
  commonName: my-root-ca
  isCA: true
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: my-root-issuer
  privateKey:
    algorithm: ECDSA
    size: 256
  secretName: my-root-ca-tls
status:
  conditions:
  - lastTransitionTime: "2024-01-08T16:53:47Z"
    message: Certificate is up to date and has not expired
    observedGeneration: 1
    reason: Ready
    status: "True"
    type: Ready
  notAfter: "2024-04-07T16:53:47Z"
  notBefore: "2024-01-08T16:53:47Z"
  renewalTime: "2024-03-08T16:53:47Z"
  revision: 1
```
</div>
{{< /clipboard >}}

The secret `cert-manager/my-root-ca-tls` will then be created and populated by `cert-manager` and will contain the root certificate and private key:

**Secret containing Root Certificate and Private Key**
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get secrets -o yaml -n cert-manager my-root-ca-tls
apiVersion: v1
data:
  ca.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FUR...
  tls.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FUR...
  tls.key: LS0tLS1CRUdJTiBFQy...
kind: Secret
metadata:
  annotations:
    cert-manager.io/alt-names: ""
    cert-manager.io/certificate-name: my-root-ca
    cert-manager.io/common-name: my-root-ca
    cert-manager.io/ip-sans: ""
    cert-manager.io/issuer-group: cert-manager.io
    cert-manager.io/issuer-kind: ClusterIssuer
    cert-manager.io/issuer-name: my-root-issuer
    cert-manager.io/uri-sans: ""
  creationTimestamp: "2024-01-08T16:51:57Z"
  labels:
    controller.cert-manager.io/fao: "true"
  name: my-root-ca-tls
  namespace: cert-manager
  resourceVersion: "1219857"
  uid: e95a1c31-f4ae-4298-bd85-17734443664a
type: kubernetes.io/tls
```
</div>
{{< /clipboard >}}

##### Create the ClusterIssuer

This secret will then be used to seed a `ClusterIssuer` to issue leaf certificates for other applications and services.
Using the `Certificate` from the previous example, you can create a `ClusterIssuer` named `my-issuer` and reference the secret `my-root-ca-tls` as the CA:

**Verrazzano ClusterIssuer**
{{< clipboard >}}
<div class="highlight">

```
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: my-issuer
spec:
  ca:
    secretName: my-root-ca-tls
```
</div>
{{< /clipboard >}}

**Example: Create a ClusterIssuer using a self-signed Root CA**
{{< clipboard >}}
<div class="highlight">

```
# Create our ClusterIssuer
$ kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: my-cluster-issuer
spec:
  ca:
    secretName: my-root-ca-tls
EOF
clusterissuer.cert-manager.io/my-issuer created

# Dislay the ClusterIssuer
% kubectl get clusterissuers.cert-manager.io -o yaml my-issuer
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"cert-manager.io/v1","kind":"ClusterIssuer","metadata":{"annotations":{},"name":"my-issuer"},"spec":{"ca":{"secretName":"my-root-ca-tls"}}}
  creationTimestamp: "2024-01-08T17:03:30Z"
  generation: 1
  name: my-cluster-issuer
  resourceVersion: "1222180"
  uid: b85cbc9f-830a-48ce-8bbe-250182c467b5
spec:
  ca:
    secretName: my-root-ca-tls
status:
  conditions:
  - lastTransitionTime: "2024-01-08T17:03:30Z"
    message: Signing CA verified
    observedGeneration: 1
    reason: KeyPairVerified
    status: "True"
    type: Ready
```
</div>
{{< /clipboard >}}

##### Examples Setup

Before trying any of the examples in this section, first install `ingress-nginx` and `kube-prometheus-stack` with defaults.
###### ingress-nginx Installation

Install `ingress-nginx` as shown:

{{< clipboard >}}
<div class="highlight">

```
$ helm upgrade --install ingress-nginx ingress-nginx --repo https://kubernetes.github.io/ingress-nginx --namespace ingress-nginx --create-namespace
```
</div>
{{< /clipboard >}}

This will create a `LoadBalancer` service for the ingress controller by default.
Take note of the NGINX `LoadBalancer` service IP as that will be needed in the examples.

{{< clipboard >}}
<div class="highlight">

```
# Get the ingress LB IP for ingress-nginx-controller
$ kubectl get svc -n ingress-nginx
NAME                                 TYPE           CLUSTER-IP       EXTERNAL-IP      PORT(S)                      AGE
ingress-nginx-controller             LoadBalancer   10.131.23.57     11.22.33.44   80:31456/TCP,443:31924/TCP   4h42m
ingress-nginx-controller-admission   ClusterIP      10.131.240.245   <none>           443/TCP                      4h42m
```
</div>
{{< /clipboard >}}

###### kube-prometheus-stack Installation

First, install `kube-prometheus-stack` with a default Prometheus instance; we will use the `kube-prometheus-stack-prometheus` service to be the backend for the ingress.

{{< clipboard >}}
<div class="highlight">

```
$ helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
$ helm repo update
$ helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack -n monitoring --create-namespace
```
</div>
{{< /clipboard >}}

This will create a default Prometheus instance `kube-prometheus-stack-prometheus`:

{{< clipboard >}}
<div class="highlight">

```
# By default kube-stack-prometheus will create a Prometheus instance OOTB with a ClusterIP service

$ kubectl get -n monitoring prometheus                     
NAME                               VERSION   DESIRED   READY   RECONCILED   AVAILABLE   AGE
kube-prometheus-stack-prometheus   v2.48.1   1         1       True         True        25h

$ kubectl get -n monitoring statefulsets.apps
NAME                                              READY   AGE
alertmanager-kube-prometheus-stack-alertmanager   1/1     25h
prometheus-kube-prometheus-stack-prometheus       1/1     25h

$ kubectl get svc -n monitoring kube-prometheus-stack-prometheus
NAME                               TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)             AGE
kube-prometheus-stack-prometheus   ClusterIP   10.137.197.169   <none>        9090/TCP,8080/TCP   25h
```
</div>
{{< /clipboard >}}

##### Example: Securing a Prometheus Instance using Ingress Annotations

This example uses ingress annotations with the `ClusterIssuer` created previously to secure ingress to a Prometheus instance.  The ingress will use the wildcard DNS service [`nip.io`](https://nip.io/) to create an address that will forward requests to the Prometheus ClusterIP service;  the ingress will have CM annotations to issue a certificate for that host using the `nip.io` hostname.  The `nip.io` service is a public DNS provider that will accept hostnames with an embedded IP address and return that address during name resolution.  For example DNS requests to resolve `myhost.11.22.33.44.nip.io` will return `11.22.33.44` as the resolved IP.

Apply the following YAML to configure an ingress for `prometheus.<your-ip>.nip.io` to forward requests to your Prometheus `ClusterIP` service, and provide the Cert-Manager annotations to generate a leaf SSL certificate for the endpoint:

{{< clipboard >}}
<div class="highlight">

```
# Creates an Ingress that will forward requests for prometheus.11.22.33.44.nip.io to the Prometheus backend
# - Use Cert-Manager ingress annotations to create a TLS certificate for the ingress endpoint signed by the my-cluster-issuer ClusterIssuer
#
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    cert-manager.io/cluster-issuer: my-cluster-issuer
    cert-manager.io/common-name: prometheus.11.22.33.44.nip.io
  name: prometheus
  namespace: monitoring
spec:
  ingressClassName: nginx
  rules:
  - host: prometheus.11.22.33.44.nip.io
    http:
      paths:
      - backend:
          service:
            name: kube-prometheus-stack-prometheus
            port:
              number: 9090
        path: /
        pathType: Prefix
  tls:
  - hosts:
    - prometheus.11.22.33.44.nip.io
    secretName: kube-prometheus-stack-prometheus-tls
```
</div>
{{< /clipboard >}}

You should now be able to access the Prometheus ingress endpoint.  From a browser, you will be asked to accept the certificate as it is signed by an untrusted root CA:

{{< clipboard >}}
<div class="highlight">

```
$ curl -k https://prometheus.11.22.33.44.nip.io
<a href="/graph">Found</a>.
```
</div>
{{< /clipboard >}}

![](/docs/guides/migrate/images/prometheus-ingress.png)

![](/docs/guides/migrate/images/Screenshot.png)

##### Example: Securing hello-helidon Using Ingress Annotations

This example uses the `ClusterIssuer` to secure the `hello-helidon` application.  In this example, we are using the IP `11.22.33.44` to represent the actual NGINX `LoadBalancer` service external IP.  You should replace this with your actual LB IP.

Deploy `hello-helidon` using a simple deployment and service with an ingress, using an `nip.io` address that points to the `ingress-nginx` LB endpoint.  The ingress also is configured with the Cert-Manager annotations to generate a leaf SSL certificate for the application endpoint:

**Helidon deployment, service, and ingress**
{{< clipboard >}}
<div class="highlight">

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hello-helidon-ocne2
  namespace: hello-helidon
spec:
  selector:
    matchLabels:
      app: app
  replicas: 3
  template:
    metadata:
      labels:
        app: app
    spec:
      containers:
      - name: app
        image: ghcr.io/verrazzano/example-helidon-greet-app-v1:1.0.0-1-20230126194830-31cd41f
        imagePullPolicy: Always
        ports:
        - name: app
          containerPort: 8080
          protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  name: hello-helidon-ocne
  namespace: hello-helidon
  labels:
    app: app
  annotations:
    service.beta.kubernetes.io/oci-load-balancer-shape: "flexible"
    service.beta.kubernetes.io/oci-load-balancer-shape-flex-min: "10"
    service.beta.kubernetes.io/oci-load-balancer-shape-flex-max: "100"
spec:
  type: ClusterIP
  ports:
  - port: 8080
  selector:
    app: app
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    app: app
    cert-manager.io/cluster-issuer: my-cluster-issuer
    cert-manager.io/common-name: hello-helidon.11.22.33.44.nip.io
  name: hello-helidon-ocne
  namespace: hello-helidon
spec:
  ingressClassName: nginx
  rules:
  - host: hello-helidon.11.22.33.44.nip.io
    http:
      paths:
      - backend:
          service:
            name: hello-helidon-ocne
            port:
              number: 8080
        path: /
        pathType: Prefix
  tls:
  - hosts:
    - hello-helidon.11.22.33.44.nip.io
    secretName: hello-helidon-tls
```
</div>
{{< /clipboard >}}

This results in the certificate `hello-helidon-tls` being created in the `hello-helidon` namespace:

**Generated Helidon ingress certificate**
{{< clipboard >}}
<div class="highlight">

```
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  creationTimestamp: "2024-01-10T19:38:24Z"
  generation: 1
  name: hello-helidon-tls
  namespace: hello-helidon
  ownerReferences:
  - apiVersion: networking.k8s.io/v1
    blockOwnerDeletion: true
    controller: true
    kind: Ingress
    name: hello-helidon-ocne
    uid: 5a865f3a-572d-44ee-9a21-eadd87486467
  resourceVersion: "1948379"
  uid: 8dbf0077-dfa7-41df-904d-ed0dd832abe9
spec:
  commonName: hello-helidon.11.22.33.44.nip.io
  dnsNames:
  - hello-helidon.11.22.33.44.nip.io
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: my-cluster-issuer
  secretName: hello-helidon-tls
  usages:
  - digital signature
  - key encipherment
status:
  conditions:
  - lastTransitionTime: "2024-01-10T19:38:24Z"
    message: Certificate is up to date and has not expired
    observedGeneration: 1
    reason: Ready
    status: "True"
    type: Ready
  notAfter: "2024-04-09T19:38:24Z"
  notBefore: "2024-01-10T19:38:24Z"
  renewalTime: "2024-03-10T19:38:24Z"
  revision: 1
```
</div>
{{< /clipboard >}}

The endpoint can now be accessed using `hello-helidon.<ip-address>.nip.io`.  As with the Prometheus example, when using the browser you will be asked to accept the certificate as it has been signed by an untrusted root CA:

{{< clipboard >}}
<div class="highlight">

```
$ curl -k https://hello-helidon.11.22.33.44.nip.io/greet        
{"message":"Hello World!"}
```
</div>
{{< /clipboard >}}

![](/docs/guides/migrate/images/helidon-browser.png)

![](/docs/guides/migrate/images/helidon-certificate-browser.png)

#### Let's Encrypt Staging with OCI DNS ClusterIssuer

To create a `ClusterIssuer` using Let's Encrypt with OCI DNS you must:

- [Install the cert-manager-oci-webhook](#installing-the-oci-dns-webhook-solver).
- Create an OCI user-principal secret, as documented [here]({{< relref "/docs/networking/traffic/dns#create-an-oracle-cloud-infrastructure-api-secret-in-the-target-cluster" >}}) in the `clusterResourceNamespace` for the Cert-Manager installation.

The following example creates a Let's Encrypt Staging cluster issuer that:

- Uses the OCI DNS zone `mydns.io`
- Specifies the OCI compartment containing the OCI DNS zone
- References the secret `ocicreds` and data field secret `oci.yaml` file containing valid OCI API credentials
- Uses the Let's Encrypt Staging environment for signing certificates

{{< clipboard >}}
<div class="highlight">

```
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: my-cluster-issuer
spec:
  acme:
    email: xxxxxxx@oracle.com
    preferredChain: ""
    privateKeySecretRef:
      name: my-lestaging-acme-secret
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    solvers:
    - dns01:
        webhook:
          config:
            compartmentOCID: ocid1.compartment.oc1...
            ociProfileSecretKey: oci.yaml
            ociProfileSecretName: ocicreds
            ociZoneName: foo.io
            useInstancePrincipals: false
          groupName: verrazzano.io
          solverName: oci
```
</div>
{{< /clipboard >}}

##### Example: Securing a Prometheus Instance using Ingress Annotations

Before trying the example be sure to follow the instructions in the [examples setup](#examples-setup) section.
This example uses ingress annotations with Let's Encrypt `ClusterIssuer` to secure ingress to a Prometheus instance.

First, create the following DNS records in your OCI DNS zone so that DNS requests can be resolved to the `ingress-nginx` ingress controller `LoadBalancer` service:

- An A record `ingress.devocne1.foo.io` pointing to the Ingress controller LB IP
- A CNAME record `prometheus.devocne1.foo.io` pointing to `ingress.devocne1.foo.io`

![](/docs/guides/migrate/images/dns-zone-records.png)

Next create an ingress for the Prometheus instance for prometheus.devocne1.foo.io with the appropriate Cert-Manager annotations:

**Prometheus ingress**
{{< clipboard >}}
<div class="highlight">

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    cert-manager.io/cluster-issuer: my-cluster-issuer
    cert-manager.io/common-name: prometheus.devocne1.foo.io
  name: kube-prometheus-stack-prometheus
  namespace: monitoring
spec:
  ingressClassName: nginx
  rules:
  - host: prometheus.devocne1.foo.io
    http:
      paths:
      - backend:
          service:
            name: kube-prometheus-stack-prometheus
            port:
              number: 9090
        path: /
        pathType: Prefix
  tls:
  - hosts:
    - prometheus.devocne1.foo.io
    secretName: kube-prometheus-stack-prometheus-tls
```
</div>
{{< /clipboard >}}

Wait a few minutes for the certificate to be signed and reach the READY state; it likely will take 3-5 minutes.

**Certificate status**
{{< clipboard >}}
<div class="highlight">

```
$ kubectl  get certificate -n monitoring
NAME                                   READY   SECRET                                 AGE
kube-prometheus-stack-prometheus-tls   True    kube-prometheus-stack-prometheus-tls   7m

$ cmctl status certificate -n monitoring kube-prometheus-stack-prometheus-tls
Name: kube-prometheus-stack-prometheus-tls
Namespace: monitoring
Created at: 2024-01-10T22:39:56Z
Conditions:
  Ready: True, Reason: Ready, Message: Certificate is up to date and has not expired
DNS Names:
- prometheus.devocne1.foo.io
Events:
  Type    Reason     Age   From                                       Message
  ----    ------     ----  ----                                       -------
  Normal  Issuing    39m   cert-manager-certificates-trigger          Issuing certificate as Secret does not exist
  Normal  Generated  39m   cert-manager-certificates-key-manager      Stored new private key in temporary Secret resource "kube-prometheus-stack-prometheus-tls-hk87w"
  Normal  Requested  39m   cert-manager-certificates-request-manager  Created new CertificateRequest resource "kube-prometheus-stack-prometheus-tls-1"
  Normal  Issuing    31m   cert-manager-certificates-issuing          The certificate has been successfully issued
Issuer:
  Name: my-cluster-issuer
  Kind: ClusterIssuer
  Conditions:
    Ready: True, Reason: ACMEAccountRegistered, Message: The ACME account was registered with the ACME server
  Events:  <none>
Secret:
  Name: kube-prometheus-stack-prometheus-tls
  Issuer Country: US
  Issuer Organisation: (STAGING) Let's Encrypt
  Issuer Common Name: (STAGING) Artificial Apricot R3
  Key Usage: Digital Signature, Key Encipherment
  Extended Key Usages: Server Authentication, Client Authentication
  Public Key Algorithm: RSA
  Signature Algorithm: SHA256-RSA
  Subject Key ID: 9f461b868d4a4282051a54fea434ee4d50f7428d
  Authority Key ID: de727a48df31c3a650df9f8523df57374b5d2e65
  Serial Number: 2b17645a0bfa248f3ba0317233a71fb1f89d
  Events:  <none>
Not Before: 2024-01-10T21:47:30Z
Not After: 2024-04-09T21:47:29Z
Renewal Time: 2024-03-10T21:47:29Z
No CertificateRequest found for this Certificate
```
</div>
{{< /clipboard >}}

After it's active, the endpoint should be reachable with a valid Let's Encrypt staging certificate; note that when using the browser you will be asked to accept the certificate as it has been signed by an untrusted root CA:

![](/docs/guides/migrate/images/prometheus-le-staging.png)
