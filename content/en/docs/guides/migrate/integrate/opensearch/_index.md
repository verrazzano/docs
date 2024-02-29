---
title: "OpenSearch"
weight: 1
draft: false
---
This document shows you how to integrate OpenSearch with other OCNE components.

## Ingress
Ingress exposes HTTP and HTTPS routes from outside the cluster to services within the cluster. Traffic routing is controlled by the rules defined on the Ingress resource. Please refer to [Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/) for more details.

#### Create Ingress to forward requests to OpenSearch and OpenSearch Dashboards
The following example creates two Ingress to forward requests to the OpenSearch and OpenSearch Dashboards backend, using cert-manager ingress annotations to create a TLS certificate for the endpoint signed by `my-cluster-issuer` ClusterIssuer.

The instructions assume:
1. Cert Manager is installed and a ClusterIssuer `my-cluster-issuer` is created
2. The `OpenSearch` and `OpenSearch Dashboards` are installed in `logging` namespace.
3. The OpenSearch instance is listening on default port `9200` and OpenSearch Dashboards is listening on default port `5601`.
4. Ingress Controller is installed in `ingress-nginx` namespace, with external IP `10.0.0.1`

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

The ingress in this case utilizes the wildcard DNS service [nip.io](https://nip.io/) to create an address, that will forward requests to the OpenSearch or OpenSearch Dashboards ClusterIP services.
## Istio

## Cert-Manager
If you have installed the cert-manager, you can utilise it to generate the required certificates for Opensearch that are used to secure transport-layer traffic (node-to-node communication within your cluster) and REST-layer traffic (communication between a client and a node within your cluster). TLS is optional for the REST layer and mandatory for the transport layer.

The following instructions to create certificate assume:
1. Cert Manager is installed and a ClusterIssuer `my-cluster-issuer` is created
2. Prometheus is installed in `monitoring` namespace.
3. Organisation for the certificate is `myOrg`.

### Create admin certificate for OpenSearch
Apply the following `Certificate` resource to create the Admin Certificate for OpenSearch. This will create admin certificate in `opensearch-admin-cert` secret. 

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
```
</div>
{{< /clipboard >}}

Once admin Certificate is created, you can update `spec.security.config.adminSecret.name` field in the OpenSearchCluster with the `opensearch-admin-cert` secret that contains the admin certificate.

### Create master certificate for OpenSearch nodes with master role

Apply the following `Certificate` resource to create the master Certificate for OpenSearch. This will create master certificate in `opensearch-master-cert` secret.

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
```
</div>
{{< /clipboard >}}

Once master Certificate is created, you can update `spec.security.tls.http.secret.name` field in the OpenSearchCluster with the `opensearch-master-cert` secret that contains the master certificate.

### Create node certificate for OpenSearch nodes with role other than master

Apply the following `Certificate` resource to create the node Certificate for OpenSearch. This will create node certificate in `opensearch-node-cert` secret.

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
```
</div>
{{< /clipboard >}}

Once node Certificate is created, you can update `spec.security.tls.transport.secret.name` field in the OpenSearchCluster with the `opensearch-node-cert` secret that contains the node certificate.

### Create OpenSearch Dashboards certificate

Apply the following `Certificate` resource to create the OpenSearch Dashboards Certificate to allow communication from OpenSearch Dashboards to OpenSearch nodes. This will create OpenSearch Dashboards certificate in `opensearch-dashboards-cert` secret.

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
```
</div>
{{< /clipboard >}}

Once OpenSearch Dashboards Certificate is created, you can update `spec.dashboards.tls.secret.name` field in the OpenSearchCluster with the `opensearch-dashboards-cert` secret that contains the OpenSearch Dashboards certificate.

You need to update the certificates in the OpenSearchCluster.
You can refer [Create OpenSearch Cluster with your own certificates]({{< relref "/docs/guides/migrate/install/opensearch#create-openSearch-cluster-with-your-own-certificates" >}}) that contains the example `OpenSearchCluster` that use the same certificates that we generated above.

### Create OpenSearch Client Cert for Prometheus

Create the necessary certificate for client certificate authentication through Cert-manager to enable communication between Prometheus and OpenSearch. Apply the following `Certificate` resource to create a client certificate for Prometheus. 
This assumes Prometheus Operator will be installed in the `monitoring` namespace and the organization for this certificate is `yourOrg`.

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
```
</div>
{{< /clipboard >}}

## Prometheus

Apply the following `ServiceMonitor` resource to scrape metrics from OpenSearch pods. This assumes Prometheus Operator has been installed in the `monitoring` namespace and OpenSearch has been installed in the `logging` namespace. 
It also assumes you have created an OpenSearch client certificate for Prometheus in the secret named `opensearch-monitor-cert`. See [Create OpenSearch Client Cert for Prometheus]({{< relref "/docs/guides/migrate/integrate/opensearch#create-openSearch-client-cert-for-prometheus" >}}).

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
```
</div>
{{< /clipboard >}}

This `ServiceMonitor` assumes OpenSearch is running in the Istio mesh. If OpenSearch is not in the Istio mesh, then remove the `tlsConfig` and change the `scheme` to `http`.

## Fluent Operator
To push the logs from the fluent-bit to OpenSearch, you need to create OpenSearch User that has access to push the logs.

### Create OpenSearch Role that has access to push logs
You need to create an `OpensearchRole` that has access to push the logs to OpenSearch. Apply the following `OpensearchRole` resource.
The instruction assume:
1. OpenSearch Operator is installed in `logging` namespace.
2. `myIndex` is index where fluentbit will push the logs.

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
```
</div>
{{< /clipboard >}}

### Create OpensearchUser for Fluentbit
Apply the following `Secret` to create the password for OpensearchUser and `OpensearchUser` to create a OpensearchUser with that password.

The following instructions create the `OpensearchUser` with name `log-pusher-user` and its password `admin` is stored as base64 encoded in `log-pusher-cred` secret.
You are suggested to use some different password.

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
{{< clipboard >}}
<div class="highlight">
```
</div>
{{< /clipboard >}}

### Create OpensearchUserRoleBinding
Create `OpensearchUserRoleBinding` to bind the OpensearchUser `log-pusher-user` that we created in previous step to OpensearchRole `log-pusher` so that it can push the logs to OpenSearch.
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
```
</div>
{{< /clipboard >}}

Now the user and password mentioned in the `log-pusher-cred` has access to push the logs.


### Configure ClusterOutput to push the logs to OpenSearch

Now, we have created OpenSearch user that has access to push the logs, we can use this user in Fluentbit ClusterOutput resource to push the logs from fluentbit to OpenSearch.

Apply the following `ClusterOutput` to allow the fluentbit to push the logs to OpenSearch.
The following instructions assume:
1. `myIndex` is OpenSearch index where fluentbit will push the logs.
2. fluentbit will search logs in  `my-namespace` namespace to push it to OpenSearch.
3. The OpenSearch instance is listening on default port `9200` and `opensearch` service is there in `logging` namespace.
4. `log-pusher-cred` secret contains the username and password for the OpensearchUser that has access to push the logs.

{{< clipboard >}}
<div class="highlight">

```
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
```
</div>
{{< /clipboard >}}