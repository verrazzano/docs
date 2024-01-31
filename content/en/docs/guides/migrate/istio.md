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

The OCNE 2.0 Istio module accepts the `spec` section of the Istio Operator custom resource. Extract all elements of the `iop.yaml` YAML files `spec` section to a new file `istio-profile.yaml`. Format that resulting YAML in the `istio-profile.yaml` file to remove two spaces from the beginning of each line and save. These two actions can be completed in one command using `yq`.

{{< clipboard >}}
<div class="highlight">

```
$ yq '.spec' < iop.yaml > istio-profile.yaml
```
</div>
{{< /clipboard >}}


<details>
<summary><b>Example istio-profile.yaml file</b></summary>

{{< clipboard >}}
<div class="highlight">

```
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
      replicaCount: 2
      securityContext:
        runAsGroup: "1337"
        runAsNonRoot: true
        runAsUser: "1337"
        seccompProfile:
          type: RuntimeDefault
      service:
        externalIPs:
        - bb.bb.bb.bb1
        - bb.bb.bb.bb2
        - bb.bb.bb.bb3
        - bb.bb.bb.bb4
        ports:
        - name: status-port
          nodePort: 30905
          port: 15021
          protocol: TCP
          targetPort: 15021
        - name: http2
          nodePort: 31380
          port: 80
          protocol: TCP
          targetPort: 8080
        - name: https
          nodePort: 31390
          port: 443
          protocol: TCP
          targetPort: 8443
        - name: nport1
          nodePort: 30126
          port: 8126
          protocol: TCP
          targetPort: 8126
        - name: nport2
          nodePort: 30182
          port: 8182
          protocol: TCP
          targetPort: 8182
        - name: nport3
          nodePort: 30184
          port: 8184
          protocol: TCP
          targetPort: 8184
        - name: nport4
          nodePort: 30132
          port: 8132
          protocol: TCP
          targetPort: 8132
        - name: nport5
          nodePort: 30134
          port: 8134
          protocol: TCP
          targetPort: 8134
        - name: nport6
          nodePort: 30128
          port: 8128
          protocol: TCP
          targetPort: 8128
        - name: nport7
          nodePort: 30146
          port: 8146
          protocol: TCP
          targetPort: 8146
        - name: nport8
          nodePort: 30194
          port: 8194
          protocol: TCP
          targetPort: 8194
        - name: nport9
          nodePort: 31782
          port: 29782
          protocol: TCP
          targetPort: 29782
        - name: nport10
          nodePort: 31753
          port: 29753
          protocol: TCP
          targetPort: 29753
        - name: nport11
          nodePort: 30153
          port: 8153
          protocol: TCP
          targetPort: 8153
        - name: nport12
          nodePort: 30196
          port: 8196
          protocol: TCP
          targetPort: 8196
        - name: nport13
          nodePort: 30159
          port: 8159
          protocol: TCP
          targetPort: 8159
        - name: nport14
          nodePort: 30198
          port: 8198
          protocol: TCP
          targetPort: 8198
        - name: nport15
          nodePort: 30130
          port: 8130
          protocol: TCP
          targetPort: 8130
        - name: nport16
          nodePort: 30185
          port: 8185
          protocol: TCP
          targetPort: 8185
        - name: nport17
          nodePort: 31707
          port: 29707
          protocol: TCP
          targetPort: 29707
        - name: nport18
          nodePort: 31708
          port: 29708
          protocol: TCP
          targetPort: 29708
        - name: nport19
          nodePort: 30180
          port: 8180
          protocol: TCP
          targetPort: 8180
        - name: nport20
          nodePort: 30139
          port: 8139
          protocol: TCP
          targetPort: 8139
        - name: nport21
          nodePort: 31701
          port: 29701
          protocol: TCP
          targetPort: 29701
        - name: nport22
          nodePort: 31703
          port: 29703
          protocol: TCP
          targetPort: 29703
        - name: nport23
          nodePort: 30169
          port: 8169
          protocol: TCP
          targetPort: 8169
        - name: nport24
          nodePort: 30142
          port: 8142
          protocol: TCP
          targetPort: 8142
        - name: nport25
          nodePort: 30120
          port: 8120
          protocol: TCP
          targetPort: 8120
        - name: nport26
          nodePort: 30167
          port: 8167
          protocol: TCP
          targetPort: 8167
        - name: nport27
          nodePort: 30122
          port: 8122
          protocol: TCP
          targetPort: 8122
        - name: nport28
          nodePort: 30135
          port: 8135
          protocol: TCP
          targetPort: 8135
        - name: nport29
          nodePort: 30192
          port: 8192
          protocol: TCP
          targetPort: 8192
        - name: nport30
          nodePort: 30189
          port: 8189
          protocol: TCP
          targetPort: 8189
        - name: nport31
          nodePort: 30136
          port: 8136
          protocol: TCP
          targetPort: 8136
        - name: nport32
          nodePort: 30154
          port: 8154
          protocol: TCP
          targetPort: 8154
        - name: nport33
          nodePort: 30158
          port: 8158
          protocol: TCP
          targetPort: 8158
        - name: nport34
          nodePort: 30172
          port: 8172
          protocol: TCP
          targetPort: 8172
        - name: nport35
          nodePort: 30177
          port: 8177
          protocol: TCP
          targetPort: 8177
        - name: nport36
          nodePort: 30282
          port: 8282
          protocol: TCP
          targetPort: 8282
        - name: nport37
          nodePort: 31882
          port: 29882
          protocol: TCP
          targetPort: 29882
        - name: nport38
          nodePort: 30296
          port: 8296
          protocol: TCP
          targetPort: 8296
        - name: nport39
          nodePort: 30280
          port: 8280
          protocol: TCP
          targetPort: 8280
        - name: nport40
          nodePort: 31801
          port: 29801
          protocol: TCP
          targetPort: 29801
        - name: nport41
          nodePort: 30284
          port: 8284
          protocol: TCP
          targetPort: 8284
        - name: nport42
          nodePort: 30236
          port: 8236
          protocol: TCP
          targetPort: 8236
        - name: nport43
          nodePort: 30232
          port: 8232
          protocol: TCP
          targetPort: 8232
        - name: nport44
          nodePort: 30267
          port: 8267
          protocol: TCP
          targetPort: 8267
        - name: nport45
          nodePort: 30234
          port: 8234
          protocol: TCP
          targetPort: 8234
        - name: nport46
          nodePort: 30298
          port: 8298
          protocol: TCP
          targetPort: 8298
        - name: nport47
          nodePort: 30230
          port: 8230
          protocol: TCP
          targetPort: 8230
        - name: nport48
          nodePort: 30285
          port: 8285
          protocol: TCP
          targetPort: 8285
        - name: nport49
          nodePort: 31807
          port: 29807
          protocol: TCP
          targetPort: 29807
        - name: nport50
          nodePort: 30246
          port: 8246
          protocol: TCP
          targetPort: 8246
        - name: nport51
          nodePort: 30294
          port: 8294
          protocol: TCP
          targetPort: 8294
        - name: nport52
          nodePort: 30228
          port: 8228
          protocol: TCP
          targetPort: 8228
        - name: nport53
          nodePort: 30242
          port: 8242
          protocol: TCP
          targetPort: 8242
        - name: nport54
          nodePort: 30220
          port: 8220
          protocol: TCP
          targetPort: 8220
        - name: nport55
          nodePort: 30254
          port: 8254
          protocol: TCP
          targetPort: 8254
        - name: nport56
          nodePort: 30222
          port: 8222
          protocol: TCP
          targetPort: 8222
        - name: nport57
          nodePort: 30292
          port: 8292
          protocol: TCP
          targetPort: 8292
        - name: nport58
          nodePort: 30289
          port: 8289
          protocol: TCP
          targetPort: 8289
        - name: nport59
          nodePort: 30188
          port: 8188
          protocol: TCP
          targetPort: 8188
        - name: nport60
          nodePort: 30152
          port: 8152
          protocol: TCP
          targetPort: 8152
        - name: nport61
          nodePort: 30160
          port: 8160
          protocol: TCP
          targetPort: 8160
        - name: nport62
          nodePort: 30162
          port: 8162
          protocol: TCP
          targetPort: 8162
        - name: nport63
          nodePort: 30151
          port: 8151
          protocol: TCP
          targetPort: 8151
        - name: nport64
          nodePort: 30163
          port: 8163
          protocol: TCP
          targetPort: 8163
        - name: nport65
          nodePort: 30165
          port: 8165
          protocol: TCP
          targetPort: 8165
        - name: nport66
          nodePort: 30178
          port: 8178
          protocol: TCP
          targetPort: 8178
        - name: nport67
          nodePort: 30179
          port: 8179
          protocol: TCP
          targetPort: 8179
        - name: nport68
          nodePort: 30140
          port: 8140
          protocol: TCP
          targetPort: 8140
        - name: nport69
          nodePort: 30150
          port: 8150
          protocol: TCP
          targetPort: 8150
        - name: nport70
          nodePort: 31709
          port: 29709
          protocol: TCP
          targetPort: 29709
        - name: nport71
          nodePort: 31714
          port: 29714
          protocol: TCP
          targetPort: 29714
        - name: nport72
          nodePort: 31713
          port: 29713
          protocol: TCP
          targetPort: 29713
        - name: nport73
          nodePort: 31719
          port: 29719
          protocol: TCP
          targetPort: 29719
        - name: nport74
          nodePort: 31718
          port: 29718
          protocol: TCP
          targetPort: 29718
        - name: nport75
          nodePort: 31711
          port: 29711
          protocol: TCP
          targetPort: 29711
        - name: nport76
          nodePort: 31704
          port: 29704
          protocol: TCP
          targetPort: 29704
        - name: nport77
          nodePort: 31721
          port: 29721
          protocol: TCP
          targetPort: 29721
        - name: nport78
          nodePort: 30288
          port: 8288
          protocol: TCP
          targetPort: 8288
        - name: nport79
          nodePort: 30252
          port: 8252
          protocol: TCP
          targetPort: 8252
        - name: nport80
          nodePort: 30260
          port: 8260
          protocol: TCP
          targetPort: 8260
        - name: nport81
          nodePort: 30262
          port: 8262
          protocol: TCP
          targetPort: 8262
        - name: nport82
          nodePort: 30251
          port: 8251
          protocol: TCP
          targetPort: 8251
        - name: nport83
          nodePort: 30263
          port: 8263
          protocol: TCP
          targetPort: 8263
        - name: nport84
          nodePort: 30265
          port: 8265
          protocol: TCP
          targetPort: 8265
        - name: nport85
          nodePort: 30240
          port: 8240
          protocol: TCP
          targetPort: 8240
        - name: nport86
          nodePort: 31804
          port: 29804
          protocol: TCP
          targetPort: 29804
        - name: nport87
          nodePort: 31813
          port: 29813
          protocol: TCP
          targetPort: 29813
        - name: nport88
          nodePort: 31819
          port: 29819
          protocol: TCP
          targetPort: 29819
        - name: nport89
          nodePort: 31818
          port: 29818
          protocol: TCP
          targetPort: 29818
        - name: nport90
          nodePort: 31712
          port: 29712
          protocol: TCP
          targetPort: 29712
        - name: nport91
          nodePort: 31812
          port: 29812
          protocol: TCP
          targetPort: 29812
        - name: nport92
          nodePort: 30174
          port: 8174
          protocol: TCP
          targetPort: 8174
        - name: nport93
          nodePort: 30274
          port: 8274
          protocol: TCP
          targetPort: 8274
        - name: nport94
          nodePort: 30275
          port: 8275
          protocol: TCP
          targetPort: 8275
        - name: nport95
          nodePort: 30175
          port: 8175
          protocol: TCP
          targetPort: 8175
        - name: nport96
          nodePort: 32020
          port: 27401
          protocol: TCP
          targetPort: 27401
        - name: nport97
          nodePort: 32021
          port: 27421
          protocol: TCP
          targetPort: 27421
        - name: nport98
          nodePort: 32022
          port: 27431
          protocol: TCP
          targetPort: 27431
        - name: nport99
          nodePort: 32024
          port: 27601
          protocol: TCP
          targetPort: 27601
        - name: nport100
          nodePort: 32025
          port: 27402
          protocol: TCP
          targetPort: 27402
        type: NodePort
    name: istio-ingressgateway
  istiodRemote:
    enabled: false
  pilot:
    enabled: true
    k8s:
      affinity:
        nodeAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - preference:
              matchExpressions:
              - key: node-type
                operator: In
                values:
                - fc-csi
            weight: 100
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - podAffinityTerm:
              labelSelector:
                matchLabels:
                  app: istiod
              topologyKey: kubernetes.io/hostname
            weight: 100
      env:
      - name: PILOT_ENABLE_CONFIG_DISTRIBUTION_TRACKING
        value: "true"
      - name: PILOT_ENABLE_STATUS
        value: "true"
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
      replicaCount: 2
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
      enableAnalysis: true
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
    tag: 1.19.0-20231002202943-1a85d369
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
    env:
      PILOT_ENABLE_CONFIG_DISTRIBUTION_TRACKING: true
      PILOT_ENABLE_STATUS: true
    image: ghcr.io/verrazzano/pilot:1.19.0-20231002202943-1a85d369
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
