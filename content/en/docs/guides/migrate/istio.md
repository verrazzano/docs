---
title: "Istio"
linkTitle: "Istio"
description: "Use this guide to migrate Istio to OCNE"
weight: 3
draft: false
---

## Overview

The following is a migration guide from the Verrazzano 1.6 Istio component to an OCNE 2.0 Istio module. The OCNE 2.0 Istio module uses the Istio Operator custom resource to customize the installation of Istio into Kubernetes. This guide walks you through retrieving the current Verrazzano installed version of the Istio Operator custom resource and editing it for use in the `olcnectl module create` command. There are also instructions for duplicating the peer authentication mode used in Verrazzano, as well as, a configuration for allowing HTTP server header pass-through within the Envoy proxy boundaries of Istio.

## Verrazzano background

Verrazzano installs Istio as a component. Internally, Verrazzano uses `istioctl` to install Istio using the Istio Operator resource. The resource is generated from the Istio defaults and the overrides from the Verrazzano custom resource Istio component section. Verrazzano installs a default peer authentication policy in strict mode. This enforces an mTLS connection between the Istio gateway and the Istio sidecar at the application pod by default.

## Migration preparation

Retrieve Istio Operator custom resource YAML from the current Verrazzano installation.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl -n istio-system get istiooperators installed-state -o yaml > iop.yaml
```
</div>
{{< /clipboard >}}

See the following `iop.yaml` file; note that this file will be different based on your Istio overrides.

<details>
<summary><b>Example iop.yaml file</b></summary>

{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
metadata:
  name: installed-state
  namespace: istio-system
  ...
spec:
  components:
    base:
      enabled: true
    cni:
      enabled: false
    egressGateways:
    - enabled: true
      k8s:
        affinity:
          podAntiAffinity:
            preferredDuringSchedulingIgnoredDuringExecution:
            - podAffinityTerm:
                labelSelector:
                  matchExpressions:
                  - key: app
                    operator: In
                    values:
                    - istio-egressgateway
                topologyKey: kubernetes.io/hostname
              weight: 100
        overlays:
        - kind: Deployment
          name: istio-egressgateway
          patches:
          - path: spec.template.spec.containers.[name:istio-proxy].securityContext
            value: |
              privileged: false
              allowPrivilegeEscalation: false
              capabilities:
                drop:
                  - ALL
        replicaCount: 1
        securityContext:
          runAsGroup: "1337"
          runAsNonRoot: true
          runAsUser: "1337"
          seccompProfile:
            type: RuntimeDefault
      name: istio-egressgateway
    ingressGateways:
    - enabled: true
      k8s:
        affinity:
          podAntiAffinity:
            preferredDuringSchedulingIgnoredDuringExecution:
            - podAffinityTerm:
                labelSelector:
                  matchExpressions:
                  - key: app
                    operator: In
                    values:
                    - istio-ingressgateway
                topologyKey: kubernetes.io/hostname
              weight: 100
        overlays:
        - kind: Deployment
          name: istio-ingressgateway
          patches:
          - path: spec.template.spec.containers.[name:istio-proxy].securityContext
            value: |
              privileged: false
              allowPrivilegeEscalation: false
              capabilities:
                drop:
                  - ALL
        replicaCount: 1
        securityContext:
          runAsGroup: "1337"
          runAsNonRoot: true
          runAsUser: "1337"
          seccompProfile:
            type: RuntimeDefault
        service:
          type: LoadBalancer
      name: istio-ingressgateway
    istiodRemote:
      enabled: false
    pilot:
      enabled: true
      k8s:
        affinity:
          podAntiAffinity:
            preferredDuringSchedulingIgnoredDuringExecution:
            - podAffinityTerm:
                labelSelector:
                  matchLabels:
                    app: istiod
                topologyKey: kubernetes.io/hostname
              weight: 100
        overlays:
        - kind: Deployment
          name: istiod
          patches:
          - path: spec.template.spec.containers.[name:discovery].securityContext
            value: |
              privileged: false
              allowPrivilegeEscalation: false
              capabilities:
                drop:
                  - ALL
        securityContext:
          runAsGroup: "1337"
          runAsNonRoot: true
          runAsUser: "1337"
          seccompProfile:
            type: RuntimeDefault
  hub: docker.io/istio
  meshConfig:
    defaultConfig:
      proxyMetadata: {}
      tracing:
        tlsSettings:
          mode: ISTIO_MUTUAL
        zipkin:
          address: jaeger-operator-jaeger-collector.verrazzano-monitoring.svc.cluster.local.:9411
    enablePrometheusMerge: true
  profile: default
  tag: 1.19.0
  values:
    base:
      enableCRDTemplates: false
      validationURL: ""
    defaultRevision: ""
    gateways:
      istio-egressgateway:
        autoscaleEnabled: false
        env:
          ISTIO_META_REQUESTED_NETWORK_VIEW: external
        name: istio-egressgateway
        secretVolumes:
        - mountPath: /etc/istio/egressgateway-certs
          name: egressgateway-certs
          secretName: istio-egressgateway-certs
        - mountPath: /etc/istio/egressgateway-ca-certs
          name: egressgateway-ca-certs
          secretName: istio-egressgateway-ca-certs
        type: ClusterIP
      istio-ingressgateway:
        autoscaleEnabled: false
        env: {}
        name: istio-ingressgateway
        secretVolumes:
        - mountPath: /etc/istio/ingressgateway-certs
          name: ingressgateway-certs
          secretName: istio-ingressgateway-certs
        - mountPath: /etc/istio/ingressgateway-ca-certs
          name: ingressgateway-ca-certs
          secretName: istio-ingressgateway-ca-certs
        serviceAnnotations:
          service.beta.kubernetes.io/oci-load-balancer-internal: true
          service.beta.kubernetes.io/oci-load-balancer-security-list-management-mode: None
          service.beta.kubernetes.io/oci-load-balancer-shape: flexible
          service.beta.kubernetes.io/oci-load-balancer-shape-flex-max: "10"
          service.beta.kubernetes.io/oci-load-balancer-shape-flex-min: "10"
          service.beta.kubernetes.io/oci-load-balancer-subnet1: ocid1.subnet.oc1.iad.aaaaaaaasxecsmvaw4li6a6wic45fjjaefilsqesoddckzp4w72w4m2w7pbq
        type: LoadBalancer
    global:
      configValidation: true
      defaultNodeSelector: {}
      defaultPodDisruptionBudget:
        enabled: false
      defaultResources:
        requests:
          cpu: 10m
      hub: ghcr.io/verrazzano
      imagePullPolicy: IfNotPresent
      imagePullSecrets: []
      istioNamespace: istio-system
      istiod:
        enableAnalysis: false
      jwtPolicy: third-party-jwt
      logAsJson: false
      logging:
        level: default:info
      meshNetworks: {}
      mountMtlsCerts: false
      multiCluster:
        clusterName: ""
        enabled: false
      network: ""
      omitSidecarInjectorConfigMap: false
      oneNamespace: false
      operatorManageWebhooks: false
      pilotCertProvider: istiod
      priorityClassName: ""
      proxy:
        autoInject: enabled
        clusterDomain: cluster.local
        componentLogLevel: misc:error
        enableCoreDump: false
        excludeIPRanges: ""
        excludeInboundPorts: ""
        excludeOutboundPorts: ""
        image: proxyv2
        includeIPRanges: '*'
        logLevel: warning
        privileged: false
        readinessFailureThreshold: 90
        readinessInitialDelaySeconds: 1
        readinessPeriodSeconds: 2
        resources:
          limits:
            cpu: 2000m
            memory: 1024Mi
          requests:
            cpu: 100m
            memory: 128Mi
        statusPort: 15020
        tracer: zipkin
      proxy_init:
        image: proxyv2
      sds:
        token:
          aud: istio-ca
      sts:
        servicePort: 0
      tag: 1.19.0-1-20240102223345-96c3a993
      tracer:
        datadog: {}
        lightstep: {}
        stackdriver: {}
        zipkin: {}
      useMCP: false
    istiodRemote:
      injectionURL: ""
    meshConfig:
      defaultConfig:
        proxyMetadata: {}
      enablePrometheusMerge: false
    pilot:
      autoscaleEnabled: false
      autoscaleMax: 5
      autoscaleMin: 1
      configMap: true
      cpu:
        targetAverageUtilization: 80
      deploymentLabels: null
      env: {}
      image: ghcr.io/verrazzano/pilot:1.19.0-1-20240102223345-96c3a993
      keepaliveMaxServerConnectionAge: 30m
      nodeSelector: {}
      podLabels: {}
      replicaCount: 1
      traceSampling: 1
    sidecarInjectorWebhook:
      rewriteAppHTTPProbe: true
    telemetry:
      enabled: true
      v2:
        enabled: true
        metadataExchange:
          wasmEnabled: false
        prometheus:
          enabled: true
          wasmEnabled: false
        stackdriver:
          configOverride: {}
          enabled: false
          logging: false
          monitoring: false
          topology: false
```
</div>
{{< /clipboard >}}
</details>

<BR>

Edit `istio-profile.yaml` for changes in IP addresses for worker nodes, as well as, images and tags for the OCNE 2.0 versions of Istio.

Copy this edited file to the new API server of the new OCNE 2.0 cluster.

## OCNE 2.0 Istio module installation

After installing the Kubernetes module:

- Create the Istio module in the new cluster.
- Change `myenvironment` to the name of the OCNE environment.
- Change `mycluster` to the name of the Kubernetes module.

{{< clipboard >}}
<div class="highlight">

```
$ olcnectl module create \
--environment-name myenvironment \
--module istio \
--name istio-system \
--istio-kubernetes-module mycluster \
--istio-profile /path/to/file/istio-profile.yaml

olcnectl module install \
--environment-name myenvironment \
--name istio-system
```
</div>
{{< /clipboard >}}

## Verrazzano parity configuration

Peer authentication defines how traffic will be tunneled (mTLS) to the Istio sidecar. By default, Verrazzano runs in strict mode for security purposes.

To continue the use of this mode in OCNE 2.0, create the peer authentication.

{{< clipboard >}}
<div class="highlight">

```
cat <<EOF | kubectl apply -f -
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
EOF
```
</div>
{{< /clipboard >}}

Envoy Filters are used to configure the Envoy proxy configuration within Istio. Verrazzano creates a server header filter to allow the pass through of server headers for use within the cluster.

To configure OCNE 2.0 to allow server header pass through, create Envoyfilter.

{{< clipboard >}}
<div class="highlight">

```
cat <<EOF | kubectl apply -f -
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: server-header-filter
  namespace: istio-system
spec:
  configPatches:
  - applyTo: NETWORK_FILTER
    match:
      listener:
        filterChain:
          filter:
            name: envoy.filters.network.http_connection_manager
    patch:
      operation: MERGE
      value:
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          server_header_transformation: PASS_THROUGH
EOF
```
</div>
{{< /clipboard >}}
