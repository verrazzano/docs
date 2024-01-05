---
title: "VerrazzanoCoherenceWorkload"
linkTitle: "VerrazzanoCoherenceWorkload"
description: "An overview of the Kubernetes resources Verrazzano creates for an OAM VerrazzanoCoherenceWorkload"
weight: 5
draft: false
---

Verrazzano will generate the following Kubernetes resources for an [VerrazzanoCoherenceWorkload]({{< relref "/docs/applications/oam/workloads/coherence/coherence.md" >}}):
* coherence.oracle.com/v1/Coherence


For example, the VerrazzanoCoherenceWorkload below is defined for the component `carts` of the [Sock Shop]({{< relref "/docs/examples/microservices/sock-shop.md" >}}) example.
```
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: carts
spec:
  workload:
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: VerrazzanoCoherenceWorkload
    spec:
      template:
        metadata:
          name: carts-coh
        spec:
          labels:
            app: carts-coh
            version: v1
          cluster: SockShop
          role: Carts
          replicas: 1
          image: ghcr.io/oracle/coherence-helidon-sockshop-carts:1.2.2
          imagePullPolicy: IfNotPresent
          application:
            type: helidon
          jvm:
            memory:
              heapSize: 2g
          coherence:
            logLevel: 9
            metrics:
              enabled: true
          ports:
            - name: http
              port: 7001
              service:
                name: carts
                port: 7001
              serviceMonitor:
                enabled: true
            - name: metrics
              port: 9612
              serviceMonitor:
                enabled: true
          securityContext:
            runAsUser: 1000
``` 

A Coherence resource similar to the one below will be created.
```
apiVersion: coherence.oracle.com/v1
kind: Coherence
metadata:
  annotations:
    com.oracle.coherence.operator/feature.suspend: "true"
    com.oracle.coherence.operator/version: 3.3.2
  creationTimestamp: "2024-01-05T14:30:05Z"
  finalizers:
  - coherence.oracle.com/operator
  labels:
    coherence-hash: 7dbb64885b
  name: carts-coh
  namespace: sockshop
spec:
  annotations:
    sidecar.istio.io/inject: "false"
    verrazzano.io/metricsEnabled: "true"
    verrazzano.io/metricsEnabled1: "true"
    verrazzano.io/metricsPath: /metrics
    verrazzano.io/metricsPath1: /metrics
    verrazzano.io/metricsPort: "7001"
    verrazzano.io/metricsPort1: "9612"
  application:
    type: helidon
  cluster: SockShop
  coherence:
    localPort: 7575
    localPortAdjust: 7576
    logLevel: 9
    metrics:
      enabled: true
  coherenceUtils:
    image: ghcr.io/oracle/coherence-operator:3.3.2
  configMapVolumes:
  - mountPath: /fluentd/etc/fluentd.conf
    name: fluentd-config-coherence
    readOnly: true
    subPath: fluentd.conf
  image: ghcr.io/oracle/coherence-helidon-sockshop-carts:2.0.1
  imagePullPolicy: IfNotPresent
  jvm:
    args:
    - -Dhelidon.serialFilter.ignoreFiles=true
    - -Dhelidon.serialFilter.pattern=*
    - -Dhelidon.serialFilter.failure.action=WARN
    - -Dcoherence.log=jdk
    - -Dcoherence.log.logger=com.oracle.coherence
    - -Djava.util.logging.config.file=/coherence-operator/utils/logging/logging.properties
    memory:
      heapSize: 2g
  labels:
    app: carts-coh
    app.oam.dev/component: carts
    app.oam.dev/name: sockshop-appconf
    version: v1
  ports:
  - name: http
    port: 7001
    protocol: TCP
    service:
      labels:
        app.oam.dev/component: carts
        app.oam.dev/name: sockshop-appconf
      name: carts
      port: 7001
    serviceMonitor:
      bearerTokenSecret:
        key: ""
      enabled: true
  - name: metrics
    port: 9612
    protocol: TCP
    service:
      labels:
        app.oam.dev/component: carts
        app.oam.dev/name: sockshop-appconf
    serviceMonitor:
      bearerTokenSecret:
        key: ""
      enabled: true
  replicas: 1
  role: Carts
  securityContext:
    runAsUser: 1000
  sideCars:
  - args:
    - -c
    - /etc/fluent.conf
    env:
    - name: LOG_PATH
      value: /logs
    - name: FLUENTD_CONF
      value: fluentd.conf
    - name: NAMESPACE
      value: sockshop
    - name: APP_CONF_NAME
      valueFrom:
        fieldRef:
          fieldPath: metadata.labels['app.oam.dev/name']
    - name: COMPONENT_NAME
      valueFrom:
        fieldRef:
          fieldPath: metadata.labels['app.oam.dev/component']
    image: ghcr.io/verrazzano/fluentd-kubernetes-daemonset:v1.14.5-20230922100900-8777b84
    imagePullPolicy: IfNotPresent
    name: fluentd-stdout-sidecar
    resources: {}
  volumeMounts:
  - mountPath: /logs
    name: logs
  volumes:
  - emptyDir: {}
    name: logs
```