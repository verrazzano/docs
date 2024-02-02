---
title: "cert-manager"
weight: 1
draft: false
---
This document shows you how to install cert-manager on OCNE.

Verrazzano supports the installation of [cert-manager](https://cert-manager.io/), or using a customer-managed cert-manager instance.  
Depending on the configuration, Verrazzano will install the following components:

- cert-manager
- The Verrazzano [cert-manager-webhook-oci](https://github.com/verrazzano/cert-manager-webhook-oci) webhook for signing certificates using Let's Encrypt.
- A ClusterIssuer used to sign certificates

## Install cert-manager

### Installing cert-manager using Helm
**TBD**, will be installed as a first-class CNE module and not from the app catalog

### Override recipes
The following sections show you how to override certain cert-manager default settings.

#### Installing from a private registry
**TBD** - need OCNE module private registry example

#### Configuring pod and container security
Override pod and container security default settings to limit actions that pods and containers can perform in the cluster. These settings allow pods and containers to perform only operations that are needed for them to operate successfully, and mitigate security vulnerabilities, such as privilege escalation.

For example, apply the following overrides when installing the cert-manager module in an OCNE 2.0 cluster to use security settings similar to those used by Verrazzano 1.6.

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

#### Configuring storage and resource limits and requests

Specify overrides to change the default resource (storage, cpu, memory, and such) requests and limits.

For example, to apply a custom resource requests for cert-manager pods create the following overrides file and apply it when installing the module.

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

#### Customizing the cluster ClusterResourceNamespace
Verrazzano sets the location for ClusterIssuer secrets used by cert-manager called the clusterResourceNamespace. This is the same namespace where cert-manager is installed by default but can be overridden when a custom certificate authority is used.

{{< clipboard >}}
<div class="highlight">

```
clusterResourceNamespace: my-clusterissuer
```
</div>
{{< /clipboard >}}

## Install the OCI DNS webhook solver

If you intend to use cert-manager with Let's Encrypt and OCI DNS, then you will need to install the `cert-manager-webhook-oci`  module from the OCNE application catalog.
The webhook solver is installed using the OCNE Application Catalog. The first step is to add the Application Catalog Helm repository to the cluster.

{{< clipboard >}}
<div class="highlight">

```
$ helm repo add ocne-app-catalog https://ocne-app-catalog-url
$ helm repo update
```
</div>
{{< /clipboard >}}

Next, install the Helm chart for the webhook.
{{< clipboard >}}
<div class="highlight">

```
$ helm install cert-manager-webhook-oci ocne-app-catalog/cert-manager-webhook-oci-1.0.0 -n cert-manager
```
</div>
{{< /clipboard >}}

In the previous example, it was installed into the default `cert-manager` namespace, however, this is not required.

### Helm override recipes
The following sections show you how to override certain cert-manager Helm values.

#### Changing cert-manager locations

If cert-manager or the ClusterIssuer resource is installed in a non-default namespace (something other than `cert-manager`), then these will need to be provided to the webhook installation as Helm overrides.{{< clipboard >}}
<div class="highlight">

```
$ helm install cert-manager-webhook-oci ocne-app-catalog/cert-manager-webhook-oci-1.0.0 --set certManager.namespace=my-cm --set certManager.clusterResourceNamespace=my-cluster-resources
```
</div>
{{< /clipboard >}}

#### Installing from a private registry

In order to install using a private registry (for example, in a disconnected environment), then you must override the Helm values to change the webhook image path.

For example, to install `cert-manager-webhook-oci` from a private registry at `myprivreg.com/verrazzano/cert-manager-webhook-oci`, create an overrides file with the following content and specify it using the `-f` option when running `helm upgrade --install`.
{{< clipboard >}}
<div class="highlight">

```
image:
  repository: myprivreg.com/verrazzano/cert-manager-webhook-oci
```
</div>
{{< /clipboard >}}

#### Configuring pod and container security

Override pod and container security default settings to limit actions that pods and containers can perform in the cluster. These settings allow pods and containers to perform only operations that are needed for them to operate successfully, and mitigate security vulnerabilities, such as privilege escalation.

For example, to apply security settings similar to those used by Verrazzano, in OCNE 2.0 use the following overrides by using the `-f` option when running `helm upgrade --install` on the `cert-manager-wehbook-oci` chart.
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

#### Configuring storage and resource limits and requests

Specify overrides to change the default resource (storage, cpu, memory, and such) requests and limits.
For example, to update resource requests for the webhook, create the following overrides file and provide the file using the `-f` option when running `helm upgrade --install`.
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

## Creating a ClusterIssuer

The steps in this section describe examples of how to create cert-manager `ClusterIssuers` that are functionally equivalent to those employed by Verrazzano and use them to secure endpoints.

### Self-signed `ClusterIssuer`

To create a self-signed `ClusterIssuer` similar to those used by Verrazzano, you must:

1. Create a cert-manager self-signed `Issuer` or `ClusterIssuer`.
1. Create a self-signed `root` certificate using the issuer from Step 1.
1. Create a `ClusterIssuer` using the TLS secret created by the `root` certificate object from Step 2.

The `ClusterIssuer` created in Step 3 can then be used to sign leaf certificate requests.

#### Creating a self-signed root certificate

When using self-signed certificates, you need to start with a root CA. The cert-manager [SelfSigned](https://cert-manager.io/docs/configuration/selfsigned/) issuer can be used to set this up, as described in the following sequence.

1. Create a [SelfSigned](https://cert-manager.io/docs/configuration/selfsigned/) issuer in the cert-manager namespace needed to create the root CA; if you are using a `ClusterIssuer`, then you must use the [cluster resource namespace](https://cert-manager.io/docs/configuration/#cluster-resource-namespace) (typically the namespace where cert-manager  is installed).
1. Create a certificate that refers to the issuer; if a namespace-scoped `Issuer` is used, then the `Certificate` must be created in the same namespace as the `Issuer`.

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


<details>
<summary><b>Example: Root Issuer Creation</b></summary>

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
</details>

Then create a `Certificate` to be signed by `my-root-issuer` with the TLS secret, `my-root-ca-tls`.  Because we are using a `ClusterIssuer,` the `Certificate` object should be created in the `clusterResourceNamespace`, which by default is the `cert-manager` namespace.

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

<details>
<summary><b>Example: Create Self-Signed Root Certificate</b></summary>

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
</details>

The secret `cert-manager/my-root-ca-tls` will then be created and populated by `cert-manager` and will contain the root certificate and private key.

**Secret Containing Root Certificate and Private Key**
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

#### Create the ClusterIssuer

This secret will then be used to seed a `ClusterIssuer` to issue leaf certificates for other applications and services.
Using the `Certificate` from the previous example, you can create a `ClusterIssuer` named `my-issuer` and reference the secret `my-root-ca-tls` as the CA.

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

<details>
<summary><b>Example: Create a ClusterIssuer Using a Self-Signed Root CA</b></summary>

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
</details>

### Let's Encrypt staging with OCI DNS ClusterIssuer

To create a `ClusterIssuer` using Let's Encrypt with OCI DNS, you must:

- [Install the cert-manager-oci-webhook](#installing-the-oci-dns-webhook-solver).
- Create an OCI user-principal secret, as documented [here]({{< relref "/docs/networking/traffic/dns#create-an-oracle-cloud-infrastructure-api-secret-in-the-target-cluster" >}}) in the `clusterResourceNamespace` for the cert-manager installation.

The following example creates a Let's Encrypt staging cluster issuer that:

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
