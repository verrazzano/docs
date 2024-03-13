---
title: "OpenSearch"
weight: 1
draft: false
---
This document shows you how to integrate OpenSearch with other OCNE components.

## Ingress
Ingress exposes HTTP and HTTPS routes from outside the cluster to services within the cluster. Traffic routing is controlled by the rules defined on the Ingress resource. For more information, see [Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/).

#### Create an ingress to forward requests to OpenSearch and OpenSearch Dashboards

The following example creates two `Ingress` resources to forward requests to the `OpenSearch` and `OpenSearch Dashboards` back ends. It uses cert-manager ingress annotations to generate a TLS certificate for the endpoint signed by the `my-cluster-issuer` ClusterIssuer.

The following instructions assume:
- cert-manager is installed and a ClusterIssuer `my-cluster-issuer` has been created.
- The `OpenSearch` and `OpenSearch Dashboards` are installed in the `logging` namespace.
- The OpenSearch instance is listening on the default port `9200` and OpenSearch Dashboards are listening on the default port `5601`.
- An ingress controller is installed in the `ingress-nginx` namespace with the hostname `os.10.0.0.1.nip.io`.

   {{<clipboard >}}
   <div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    cert-manager.io/cluster-issuer: my-cluster-issuer
    cert-manager.io/common-name: os.10.0.0.1.nip.io
  name: opensearch
  namespace: logging
spec:
  ingressClassName: nginx
  rules:
  - host: os.10.0.0.1.nip.io
    http:
      paths:
      - backend:
          service:
            name: opensearch
            port:
              number: 9200
        path: /()(.*)
        pathType: Prefix
  tls:
  - hosts:
    - opensearch.10.0.0.1.nip.io
    secretName: opensearch-tls
EOF
```

   </div>
   {{< /clipboard >}}

   {{<clipboard >}}
   <div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    cert-manager.io/cluster-issuer: my-cluster-issuer
    cert-manager.io/common-name: osd.10.0.0.1.nip.io
  name: opensearch-dashboards
  namespace: logging
spec:
  ingressClassName: nginx
  rules:
  - host: osd.10.0.0.1.nip.io
    http:
      paths:
      - backend:
          service:
            name: opensearch-dashboards
            port:
              number: 5601
        path: /()(.*)
        pathType: Prefix
  tls:
  - hosts:
    - opensearch.10.0.0.1.nip.io
    secretName: opensearch-dashboards-tls
EOF
```
   </div>
   {{< /clipboard >}}

In this case, the ingress uses the wildcard DNS service [nip.io](https://nip.io/) to create an address, that will forward requests to the OpenSearch or OpenSearch Dashboards ClusterIP services.

## cert-manager

If you have installed cert-manager, then you can use it to generate the required certificates for OpenSearch, which are used to secure transport-layer traffic (node-to-node communication within your cluster) and REST-layer traffic (communication between a client and a node within your cluster). TLS is optional for the REST layer and mandatory for the transport layer.

The following instructions to create certificates assume:

- cert-manager is installed and a ClusterIssuer named `my-cluster-issuer` has been created.
- The OpenSearch operator is installed in the `logging` namespace.
- The organization for the certificate is `myOrg`.

### Create admin certificate for OpenSearch

Apply the following `Certificate` resource to create the admin certificate for OpenSearch. This will create the admin certificate in the `opensearch-admin-cert` secret.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: opensearch-admin-cert
  namespace: logging
spec:
  commonName: admin
  secretName: opensearch-admin-cert
  privateKey:
    algorithm: RSA
    encoding: PKCS8
    size: 2048
  duration: 2160h0m0s
  renewBefore: 360h0m0s
  subject:
    organizations:
      - myOrg
  usages:
    - server auth
    - client auth
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: my-cluster-issuer
status: {}
EOF
```
</div>
{{< /clipboard >}}

After the admin certificate is created, you can update the `spec.security.config.adminSecret.name` field in the `OpenSearchCluster` with the `opensearch-admin-cert` secret that contains the admin certificate.

### Create master certificate for OpenSearch nodes with the master role

Apply the following `Certificate` resource to create the master certificate for OpenSearch. This will create the master certificate in the `opensearch-master-cert` secret.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: opensearch-master-cert
  namespace: logging
spec:
  commonName: opensearch
  secretName: opensearch-master-cert
  dnsNames:
    - opensearch
    - opensearch.logging
    - opensearch.logging.svc
    - opensearch.logging.svc.cluster.local
    - opensearch-discovery
  privateKey:
    algorithm: RSA
    encoding: PKCS8
    size: 2048
  renewBefore: 360h0m0s
  duration: 2160h0m0s
  subject:
    organizations:
      - myOrg
  usages:
    - server auth
    - client auth
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: my-cluster-issuer
status: {}
EOF
```
</div>
{{< /clipboard >}}

After master certificate is created, you can update the `spec.security.tls.http.secret.name` field in the OpenSearchCluster with the `opensearch-master-cert` secret that contains the master certificate.

### Create node certificate for OpenSearch nodes with roles other than master

Apply the following `Certificate` resource to create the node certificate for OpenSearch. This will create the node certificate in the `opensearch-node-cert` secret.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: opensearch-node-cert
  namespace: logging
spec:
  commonName: opensearch
  secretName: opensearch-node-cert
  dnsNames:
    - opensearch
    - opensearch.logging
    - opensearch.logging.svc
    - opensearch.logging.svc.cluster.local
  privateKey:
    algorithm: RSA
    encoding: PKCS8
    size: 2048
  renewBefore: 360h0m0s
  duration: 2160h0m0s
  subject:
    organizations:
      - myOrg
  usages:
    - server auth
    - client auth
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: my-cluster-issuer
status: {}
EOF
```
</div>
{{< /clipboard >}}

After the node Certificate is created, you can update the `spec.security.tls.transport.secret.name` field in the OpenSearchCluster with the `opensearch-node-cert` secret that contains the node certificate.

### Create OpenSearch Dashboards certificate

Apply the following `Certificate` resource to create the OpenSearch Dashboards certificate to allow communication from OpenSearch Dashboards to OpenSearch nodes. This will create OpenSearch Dashboards certificate in `opensearch-dashboards-cert` secret.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: opensearch-dashboards-cert
  namespace: logging
spec:
  commonName: opensearch
  secretName: opensearch-dashboards-cert
  dnsNames:
    - opensearch
    - opensearch.logging
    - opensearch.logging.svc
    - opensearch.logging.svc.cluster.local
  privateKey:
    algorithm: RSA
    encoding: PKCS8
    size: 2048
  renewBefore: 360h0m0s
  duration: 2160h0m0s
  subject:
    organizations:
      - myOrg
  usages:
    - server auth
    - client auth
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: my-cluster-issuer
status: {}
EOF
```
</div>
{{< /clipboard >}}

After the OpenSearch Dashboards certificate is created, you can update the `spec.dashboards.tls.secret.name` field in the OpenSearchCluster with the `opensearch-dashboards-cert` secret that contains the OpenSearch Dashboards certificate.

You need to update the certificates in the OpenSearchCluster. See [Create OpenSearch Cluster with your own certificates]({{< relref "/docs/guides/migrate/install/opensearch#create-opensearch-cluster-with-your-own-certificates" >}}) for an example `OpenSearchCluster` that uses the same certificates that we generated previously.

### Create OpenSearch client certificate for Prometheus

Create the necessary certificate for client certificate authentication through cert-manager to enable communication between Prometheus and OpenSearch. Apply the following `Certificate` resource to create a client certificate for Prometheus.

This assumes that the Prometheus Operator will be installed in the `monitoring` namespace and the organization for this certificate is `myOrg`.

This will create a client certificate for Prometheus in the `opensearch-monitor-cert` secret. You can use this secret to create `ServiceMonitor` for OpenSearch.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: opensearch-monitor-certs
  namespace: monitoring
spec:
  commonName: prometheus-operator
  secretName: opensearch-monitor-cert
  privateKey:
    algorithm: RSA
    encoding: PKCS8
    size: 2048
  renewBefore: 360h0m0s
  duration: 2160h0m0s
  subject:
    organizations:
      - myOrg
  usages:
    - server auth
    - client auth
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: my-cluster-issuer
status: {}
EOF
```
</div>
{{< /clipboard >}}

## Prometheus

Apply the following `ServiceMonitor` resource to scrape metrics from OpenSearch pods. This assumes that Prometheus Operator has been installed in the `monitoring` namespace and OpenSearch has been installed in the `logging` namespace.

The instructions assume:

- An OpenSearch client certificate for Prometheus is stored in the secret named `opensearch-monitor-cert`. See [Create OpenSearch Client Certificate for Prometheus]({{< relref "/docs/guides/migrate/integrate/opensearch#create-opensearch-client-certificate-for-prometheus" >}}).
- Prometheus Operator is installed in the `monitoring` namespace.
- OpenSearch is not running in the Istio mesh.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: opensearch
  namespace: monitoring
  labels:
    release: prometheus-operator
spec:
  namespaceSelector:
    matchNames:
      - logging
  selector: {}
  endpoints:
    - path: /_prometheus/metrics
      enableHttp2: false
      tlsConfig:
        ca:
          secret:
            name: opensearch-monitor-cert
            key: ca.crt
        cert:
          secret:
            name: opensearch-monitor-cert
            key: tls.crt
        keySecret:
          name: opensearch-monitor-cert
          key: tls.key
        insecureSkipVerify: true
      scheme: https
      relabelings:
        - sourceLabels:
            - __meta_kubernetes_pod_name
          regex: opensearch.*
          action: keep
        - sourceLabels:
            - __meta_kubernetes_pod_container_port_number
          regex: "9200"
          action: keep
        - sourceLabels:
            - __meta_kubernetes_namespace
          action: replace
          targetLabel: namespace
        - sourceLabels:
            - __meta_kubernetes_pod_name
          action: replace
          targetLabel: kubernetes_pod_name
EOF
```
</div>
{{< /clipboard >}}


## Fluent Operator
To push logs from Fluent Bit to OpenSearch, you need to create an OpenSearch user that has access to push the logs.

### Create OpenSearch role with access to push logs

You need to create an `OpensearchRole` that has access to push logs to OpenSearch. Apply the following `OpensearchRole` resource.

The instructions assume:
- OpenSearch Operator is installed in the `logging` namespace.
- `myIndex` is the index where Fluent Bit will push the logs.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: opensearch.opster.io/v1
kind: OpensearchRole
metadata:
  name: log-pusher
  namespace: logging
spec:
  opensearchCluster:
    name: opensearch
  clusterPermissions:
    - "cluster:monitor/main"
    - "cluster:monitor/state"
    - "cluster:monitor/health"
    - "cluster_manage_index_templates"
    - "indices:admin/index_template/get"
    - "indices:admin/index_template/put"
    - "indices:admin/mapping/put"
    - "indices:admin/mapping/get"
    - "indices:admin/create"
  indexPermissions:
    - indexPatterns:
        - "myIndex*"
      allowedActions:
        - indices_all
EOF
```
</div>
{{< /clipboard >}}

### Create OpensearchUser for Fluent Bit
Apply the following `Secret` to create the password for OpensearchUser, and `OpensearchUser` to create an OpensearchUser with that password.

The following instructions create the `OpensearchUser` with the name `log-pusher-user` and its password `admin` is stored as base64 encoded in the `log-pusher-cred` secret.
You should use a different password.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: log-pusher-cred
  namespace: logging
type: Opaque
data:
  password: YWRtaW4K   #base64 encoded password
  username: log-pusher-user
---
apiVersion: opensearch.opster.io/v1
kind: OpensearchUser
metadata:
  name: log-pusher-user
  namespace:  <opensearch operator namespace>
spec:
  opensearchCluster:
    name: opensearch
  backendRoles:
    - log_pusher
  passwordFrom:
    key: password
    name: log-pusher-cred
EOF
```
</div>
{{< /clipboard >}}

### Create OpensearchUserRoleBinding for OpensearchUser
Create `OpensearchUserRoleBinding` to bind the OpensearchUser `log-pusher-user` that was created in the previous step to OpensearchRole `log-pusher`, so that it can push logs to OpenSearch.

Apply the following `OpensearchUserRoleBinding` resource to create the OpensearchUserRoleBinding with name `log-pusher-rb`.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: opensearch.opster.io/v1
kind: OpensearchUserRoleBinding
metadata:
  name: log-pusher-rb
  namespace:  logging
spec:
  opensearchCluster:
    name: opensearch
  backendRoles:
    - log_pusher
  roles:
    - log-pusher
  users:
    - "log-pusher-user"
EOF
```
</div>
{{< /clipboard >}}

Now the user and password in `log-pusher-cred` has access to push the logs.


### Configure ClusterOutput to push logs to OpenSearch

You have created an OpenSearch user that has access to push logs. You will use this user in the Fluent Bit ClusterOutput resource to push logs from Fluent Bit to OpenSearch.

Apply the following `ClusterOutput` to allow Fluent Bit to push logs to OpenSearch.

The following instructions assume:
- `myIndex` is the OpenSearch index where Fluent Bit will push the logs.
- Fluent Bit will search logs in the `my-namespace` namespace to push to OpenSearch.
- The OpenSearch instance is listening on default port `9200` and the `opensearch` service is there in `logging` namespace.
- The `log-pusher-cred` secret contains the user name and password for the OpensearchUser that has access to push the logs.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: fluentbit.fluent.io/v1alpha2
kind: ClusterOutput
metadata:
  name: my-clusteroutput
  labels:
    fluentbit.fluent.io/enabled: "true"
spec:
  # you need to update the matchRegex to let the fluent operator know which namespace to include to fetch the logs.
  matchRegex: '^.*my-namespace.*'
  retry_limit: "no_limits"
  opensearch:
    host: opensearch.logging
    port: 9200
    index: myIndex
    httpUser:
      valueFrom:
        secretKeyRef:
          key: username
          name: log-pusher-cred
    httpPassword: admin
      valueFrom:
        secretKeyRef:
          key: password
          name: log-pusher-cred
    suppressTypeName: true
    replaceDots: true
EOF
```
</div>
{{< /clipboard >}}
