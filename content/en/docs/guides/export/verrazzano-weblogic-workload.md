---
title: "VerrazzanoWebLogicWorkload"
linkTitle: "VerrazzanoWebLogicWorkload"
description: "An overview of the Kubernetes resources Verrazzano creates for an OAM VerrazzanoWebLogicWorkload"
weight: 5
draft: false
---

Verrazzano will generate the following Kubernetes resources for an [VerrazzanoWebLogicWorkload]({{< relref "/docs/applications/oam/workloads/weblogic/_index.md" >}}):
* weblogic.oracle/v9/Domain
  * With Fluentd sidecar container required for logging to the Domain
  * MonitoringExporter
* ConfigMap for domain


```
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: todo-domain
  namespace: mc-todo-list
spec:
  workload:
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: VerrazzanoWebLogicWorkload
    spec:
      template:
        apiVersion: weblogic.oracle/v9
        metadata:
          name: todo-domain
          namespace: mc-todo-list
        spec:
          adminServer:
            adminChannelPortForwardingEnabled: true
          domainUID: tododomain
          domainHome: /u01/domains/tododomain
          image: container-registry.oracle.com/middleware/weblogic:12.2.1.4
          imagePullSecrets:
            - name: tododomain-repo-credentials
          domainHomeSourceType: "FromModel"
          includeServerOutInPodLog: true
          replicas: 1
          webLogicCredentialsSecret:
            name: tododomain-weblogic-credentials
          configuration:
            introspectorJobActiveDeadlineSeconds: 900
            model:
              auxiliaryImages:
                - image: container-registry.oracle.com/verrazzano/example-todo:20211129200415-ae4e89e
              configMap: tododomain-jdbc-config
              domainType: WLS
              runtimeEncryptionSecret: tododomain-runtime-encrypt-secret
            secrets:
              - tododomain-jdbc-tododb
          serverPod:
            labels:
              app: todo-domain
              version: v1
            env:
              - name: JAVA_OPTIONS
                value: "-Dweblogic.StdoutDebugEnabled=false"
              - name: USER_MEM_ARGS
                value: "-Djava.security.egd=file:/dev/./urandom -Xms64m -Xmx256m "
              - name: WL_HOME
                value: /u01/oracle/wlserver
              - name: MW_HOME
                value: /u01/oracle
```



```
apiVersion: weblogic.oracle/v9
kind: Domain
metadata:
  name: todo-domain
  namespace: todo-list
spec:
  adminServer:
    adminChannelPortForwardingEnabled: true
    serverStartPolicy: IfNeeded
  configuration:
    introspectorJobActiveDeadlineSeconds: 900
    model:
      auxiliaryImages:
      - image: container-registry.oracle.com/verrazzano/example-todo:20211129200415-ae4e89e
      configMap: tododomain-jdbc-config
      domainType: WLS
      runtimeEncryptionSecret: tododomain-runtime-encrypt-secret
    overrideDistributionStrategy: Dynamic
    secrets:
    - tododomain-jdbc-tododb
  domainHome: /u01/domains/tododomain
  domainHomeSourceType: FromModel
  domainUID: tododomain
  failureRetryIntervalSeconds: 120
  failureRetryLimitMinutes: 1440
  httpAccessLogInLogHome: true
  image: container-registry.oracle.com/middleware/weblogic:12.2.1.4
  imagePullSecrets:
  - name: tododomain-repo-credentials
  includeServerOutInPodLog: true
  logHome: /scratch/logs/todo-domain
  logHomeEnabled: true
  logHomeLayout: Flat
  maxClusterConcurrentShutdown: 1
  maxClusterConcurrentStartup: 0
  maxClusterUnavailable: 1
  monitoringExporter:
    configuration:
      domainQualifier: true
      metricsNameSnakeCase: true
      queries:
      - applicationRuntimes:
          componentRuntimes:
            key: name
            prefix: wls_webapp_config_
            servlets:
              key: servletName
              prefix: wls_servlet_
            type: WebAppComponentRuntime
            values:
            - deploymentState
            - contextRoot
            - sourceInfo
            - sessionsOpenedTotalCount
            - openSessionsCurrentCount
            - openSessionsHighCount
          key: name
          keyName: app
        key: name
        keyName: location
        prefix: wls_server_
      - JVMRuntime:
          key: name
          prefix: wls_jvm_
      - executeQueueRuntimes:
          key: name
          prefix: wls_socketmuxer_
          values:
          - pendingRequestCurrentCount
      - workManagerRuntimes:
          key: name
          prefix: wls_workmanager_
          values:
          - stuckThreadCount
          - pendingRequests
          - completedRequests
      - threadPoolRuntime:
          key: name
          prefix: wls_threadpool_
          values:
          - executeThreadTotalCount
          - queueLength
          - stuckThreadCount
          - hoggingThreadCount
      - JMSRuntime:
          JMSServers:
            destinations:
              key: name
              keyName: destination
              prefix: wls_jms_dest_
            key: name
            keyName: jmsserver
            prefix: wls_jms_
          key: name
          keyName: jmsruntime
          prefix: wls_jmsruntime_
      - persistentStoreRuntimes:
          key: name
          prefix: wls_persistentstore_
      - JDBCServiceRuntime:
          JDBCDataSourceRuntimeMBeans:
            key: name
            prefix: wls_datasource_
      - JTARuntime:
          key: name
          prefix: wls_jta_
    image: ghcr.io/oracle/weblogic-monitoring-exporter:2.1.8
    imagePullPolicy: IfNotPresent
    port: 8080
  replaceVariablesInJavaOptions: false
  replicas: 1
  serverPod:
    containers:
    - args:
      - -c
      - /etc/fluent.conf
      env:
      - name: LOG_PATH
        value: /scratch/logs/todo-domain/$(SERVER_NAME).log,/scratch/logs/todo-domain/$(SERVER_NAME)_access.log,/scratch/logs/todo-domain/$(SERVER_NAME)_nodemanager.log,/scratch/logs/todo-domai
n/$(DOMAIN_UID).log
      - name: FLUENTD_CONF
        value: fluentd.conf
      - name: NAMESPACE
        value: todo-list
      - name: APP_CONF_NAME
        valueFrom:
          fieldRef:
            fieldPath: metadata.labels['app.oam.dev/name']
      - name: COMPONENT_NAME
        valueFrom:
          fieldRef:
            fieldPath: metadata.labels['app.oam.dev/component']
      - name: DOMAIN_UID
        valueFrom:
          fieldRef:
            fieldPath: metadata.labels['weblogic.domainUID']
      - name: SERVER_NAME
        valueFrom:
          fieldRef:
            fieldPath: metadata.labels['weblogic.serverName']
      - name: SERVER_LOG_PATH
        value: /scratch/logs/todo-domain/$(SERVER_NAME).log
      - name: ACCESS_LOG_PATH
        value: /scratch/logs/todo-domain/$(SERVER_NAME)_access.log
      - name: NODEMANAGER_LOG_PATH
        value: /scratch/logs/todo-domain/$(SERVER_NAME)_nodemanager.log
      - name: DOMAIN_LOG_PATH
        value: /scratch/logs/todo-domain/$(DOMAIN_UID).log
      image: ghcr.io/verrazzano/fluentd-kubernetes-daemonset:v1.14.5-20230922100900-8777b84
      imagePullPolicy: IfNotPresent
      name: fluentd-stdout-sidecar
      volumeMounts:
      - mountPath: /fluentd/etc/fluentd.conf
        name: fluentd-config-volume
        readOnly: true
        subPath: fluentd.conf
      - mountPath: /scratch
        name: weblogic-domain-storage-volume
        readOnly: true
    env:
    - name: JAVA_OPTIONS
      value: -Dweblogic.StdoutDebugEnabled=false
    - name: USER_MEM_ARGS
      value: '-Djava.security.egd=file:/dev/./urandom -Xms64m -Xmx256m '
    - name: WL_HOME
      value: /u01/oracle/wlserver
    - name: MW_HOME
      value: /u01/oracle
    labels:
      app: todo-domain
      verrazzano.io/workload-type: weblogic
      version: v1
    volumeMounts:
    - mountPath: /scratch
      name: weblogic-domain-storage-volume
    volumes:
    - configMap:
        defaultMode: 420
        name: fluentd-config-weblogic
      name: fluentd-config-volume
    - emptyDir: {}
      name: weblogic-domain-storage-volume
  serverService:
    labels:
      app: todo-domain
      verrazzano.io/workload-type: weblogic
      version: v1
  serverStartPolicy: IfNeeded
  webLogicCredentialsSecret:
    name: tododomain-weblogic-credentials
```