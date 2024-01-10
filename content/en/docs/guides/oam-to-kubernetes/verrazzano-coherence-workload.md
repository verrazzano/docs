---
title: "VerrazzanoCoherenceWorkload"
linkTitle: "VerrazzanoCoherenceWorkload"
description: "Review the Kubernetes resources Verrazzano creates for an OAM VerrazzanoCoherenceWorkload"
weight: 5
draft: false
---

Verrazzano generates the following Kubernetes resources for a [VerrazzanoCoherenceWorkload]({{< relref "/docs/applications/oam/workloads/coherence/coherence.md" >}}):
* coherence.oracle.com/v1/Coherence
* apps/v1/StatefulSet


For example, the following VerrazzanoCoherenceWorkload is defined for the component, `carts`, of the [Sock Shop]({{< relref "/docs/examples/microservices/sock-shop.md" >}}) example.
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

A Coherence resource, similar to the following one, will be created.
```
apiVersion: coherence.oracle.com/v1
kind: Coherence
metadata:
  annotations:
    com.oracle.coherence.operator/feature.suspend: "true"
    com.oracle.coherence.operator/version: 3.3.2
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

A StatefulSet resource, similar to the following one, will be created.
```
apiVersion: apps/v1
kind: StatefulSet
metadata:
  annotations:
    com.oracle.coherence.operator/feature.suspend: "true"
    com.oracle.coherence.operator/version: 3.3.2
  labels:
    coherence-hash: 7dbb64885b
    coherenceCluster: SockShop
    coherenceComponent: coherence
    coherenceDeployment: carts-coh
    coherenceRole: Carts
  name: carts-coh
  namespace: sockshop
spec:
  podManagementPolicy: Parallel
  replicas: 1
  revisionHistoryLimit: 5
  selector:
    matchLabels:
      coherenceCluster: SockShop
      coherenceComponent: coherencePod
      coherenceDeployment: carts-coh
      coherenceRole: Carts
  serviceName: carts-coh-sts
  template:
    metadata:
      annotations:
        sidecar.istio.io/inject: "false"
        verrazzano.io/metricsEnabled: "true"
        verrazzano.io/metricsEnabled1: "true"
        verrazzano.io/metricsPath: /metrics
        verrazzano.io/metricsPath1: /metrics
        verrazzano.io/metricsPort: "7001"
        verrazzano.io/metricsPort1: "9612"
      creationTimestamp: null
      labels:
        app: carts-coh
        app.oam.dev/component: carts
        app.oam.dev/name: sockshop-appconf
        coherenceCluster: SockShop
        coherenceComponent: coherencePod
        coherenceDeployment: carts-coh
        coherenceRole: Carts
        coherenceWKAMember: "true"
        version: v1
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: coherenceCluster
                  operator: In
                  values:
                  - SockShop
                - key: coherenceDeployment
                  operator: In
                  values:
                  - carts-coh
              topologyKey: topology.kubernetes.io/zone
            weight: 50
          - podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: coherenceCluster
                  operator: In
                  values:
                  - SockShop
                - key: coherenceDeployment
                  operator: In
                  values:
                  - carts-coh
              topologyKey: oci.oraclecloud.com/fault-domain
            weight: 10
          - podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: coherenceCluster
                  operator: In
                  values:
                  - SockShop
                - key: coherenceDeployment
                  operator: In
                  values:
                  - carts-coh
              topologyKey: kubernetes.io/hostname
            weight: 1
      containers:
      - command:
        - /coherence-operator/utils/runner
        - server
        env:
        - name: COH_MACHINE_NAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: spec.nodeName
        - name: COH_MEMBER_NAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.name
        - name: COH_POD_UID
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.uid
        - name: COH_ROLE
          value: Carts
        - name: COH_CLUSTER_NAME
          value: SockShop
        - name: COH_WKA
          value: carts-coh-wka.sockshop.svc
        - name: OPERATOR_HOST
          valueFrom:
            secretKeyRef:
              key: operatorhost
              name: coherence-operator-config
              optional: true
        - name: COH_SITE_INFO_LOCATION
          value: http://$(OPERATOR_HOST)/site/$(COH_MACHINE_NAME)
        - name: COH_RACK_INFO_LOCATION
          value: http://$(OPERATOR_HOST)/rack/$(COH_MACHINE_NAME)
        - name: COH_UTIL_DIR
          value: /coherence-operator/utils
        - name: OPERATOR_REQUEST_TIMEOUT
          value: "120"
        - name: COH_HEALTH_PORT
          value: "6676"
        - name: COH_IDENTITY
          value: carts-coh@sockshop
        - name: COH_APP_TYPE
          value: helidon
        - name: JVM_ARGS
          value: -Dhelidon.serialFilter.ignoreFiles=true -Dhelidon.serialFilter.pattern=*
            -Dhelidon.serialFilter.failure.action=WARN -Dcoherence.log=jdk -Dcoherence.log.logger=com.oracle.coherence
            -Djava.util.logging.config.file=/coherence-operator/utils/logging/logging.properties
        - name: JVM_HEAP_SIZE
          value: 2g
        - name: JVM_GC_LOGGING
          value: "false"
        - name: JVM_USE_CONTAINER_LIMITS
          value: "true"
        - name: COHERENCE_LOCALPORT
          value: "7575"
        - name: COHERENCE_LOCALPORT_ADJUST
          value: "7576"
        - name: COH_LOG_LEVEL
          value: "9"
        - name: COH_MGMT_ENABLED
          value: "false"
        - name: COH_METRICS_ENABLED
          value: "true"
        - name: COH_METRICS_PORT
          value: "9612"
        image: ghcr.io/oracle/coherence-helidon-sockshop-carts:2.0.1
        imagePullPolicy: IfNotPresent
        livenessProbe:
          failureThreshold: 5
          httpGet:
            path: /healthz
            port: 6676
            scheme: HTTP
          initialDelaySeconds: 60
          periodSeconds: 60
          successThreshold: 1
          timeoutSeconds: 30
        name: coherence
        ports:
        - containerPort: 7
          name: coherence
          protocol: TCP
        - containerPort: 6676
          name: health
          protocol: TCP
        - containerPort: 7575
          name: coh-local
          protocol: TCP
        - containerPort: 7574
          name: coh-cluster
          protocol: TCP
        - containerPort: 7001
          name: http
          protocol: TCP
        - containerPort: 9612
          name: metrics
          protocol: TCP
        readinessProbe:
          failureThreshold: 50
          httpGet:
            path: /ready
            port: 6676
            scheme: HTTP
          initialDelaySeconds: 30
          periodSeconds: 60
          successThreshold: 1
          timeoutSeconds: 30
        resources: {}
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
        volumeMounts:
        - mountPath: /coherence-operator/utils
          name: coh-utils
        - mountPath: /coherence-operator/jvm
          name: jvm
        - mountPath: /logs
          name: logs
        - mountPath: /fluentd/etc/fluentd.conf
          name: fluentd-config-coherence
          readOnly: true
          subPath: fluentd.conf
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
              apiVersion: v1
              fieldPath: metadata.labels['app.oam.dev/name']
        - name: COMPONENT_NAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.labels['app.oam.dev/component']
        - name: COH_MACHINE_NAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: spec.nodeName
        - name: COH_MEMBER_NAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.name
        - name: COH_POD_UID
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.uid
        - name: COH_ROLE
          value: Carts
        - name: COH_CLUSTER_NAME
          value: SockShop
        image: ghcr.io/verrazzano/fluentd-kubernetes-daemonset:v1.14.5-20230922100900-8777b84
        imagePullPolicy: IfNotPresent
        name: fluentd-stdout-sidecar
        resources: {}
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
        volumeMounts:
        - mountPath: /coherence-operator/utils
          name: coh-utils
        - mountPath: /coherence-operator/jvm
          name: jvm
        - mountPath: /logs
          name: logs
        - mountPath: /fluentd/etc/fluentd.conf
          name: fluentd-config-coherence
          readOnly: true
          subPath: fluentd.conf
      dnsPolicy: ClusterFirst
      initContainers:
      - command:
        - /files/runner
        - init
        env:
        - name: COH_UTIL_DIR
          value: /coherence-operator/utils
        - name: COH_CLUSTER_NAME
          value: SockShop
        image: ghcr.io/oracle/coherence-operator:3.3.2
        imagePullPolicy: IfNotPresent
        name: coherence-k8s-utils
        resources: {}
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
        volumeMounts:
        - mountPath: /coherence-operator/utils
          name: coh-utils
        - mountPath: /coherence-operator/jvm
          name: jvm
        - mountPath: /fluentd/etc/fluentd.conf
          name: fluentd-config-coherence
          readOnly: true
          subPath: fluentd.conf
      restartPolicy: Always
      schedulerName: default-scheduler
      securityContext:
        runAsUser: 1000
      terminationGracePeriodSeconds: 30
      volumes:
      - emptyDir: {}
        name: coh-utils
      - emptyDir: {}
        name: jvm
      - emptyDir: {}
        name: logs
      - configMap:
          defaultMode: 420
          name: fluentd-config-coherence
        name: fluentd-config-coherence
  updateStrategy:
    type: RollingUpdate
```
