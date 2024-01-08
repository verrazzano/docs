---
title: "VerrazzanoHelidonWorkload"
linkTitle: "VerrazzanoHelidonWorkload"
description: "An overview of the Kubernetes resources Verrazzano creates for an OAM VerrazzanoHelidonWorkload"
weight: 5
draft: false
---

Verrazzano will generate the following Kubernetes resources for an [VerrazzanoHelidonWorkload]({{< relref "/docs/applications/oam/workloads/helidon/helidon.md" >}}):
* apps/v1/Deployment - implements the `deploymentTemplate` portion of the VerrazzanoHelidonWorkload
* v1/Service - exposes the deployed application

For example, the VerrazzanoHelidonWorkload below is defined for the component `hello-helidon-component` of the [Hello World Helidon]({{< relref "/docs/examples/hello-helidon/_index.md" >}}) example.
```
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: hello-helidon-component
spec:
  workload:
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: VerrazzanoHelidonWorkload
    metadata:
      name: hello-helidon-workload
      labels:
        app: hello-helidon
        version: v1
    spec:
      deploymentTemplate:
        metadata:
          name: hello-helidon-deployment
        podSpec:
          containers:
            - name: hello-helidon-container
              image: "ghcr.io/verrazzano/example-helidon-greet-app-v1:1.0.0-1-20230126194830-31cd41f"
              ports:
                - containerPort: 8080
                  name: http
```

A Deployment resource similar to the one below will be created.
```
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
    deployment.kubernetes.io/revision: "1"
    description: Hello Helidon application
  labels:
    app: hello-helidon
    version: v1
  name: hello-helidon-deployment
  namespace: hello-helidon
spec:
  progressDeadlineSeconds: 600
  replicas: 1
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      verrazzanohelidonworkloads.oam.verrazzano.io: d58cca68-b131-47e2-8ea4-3923bff38efa
  strategy:
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25%
    type: RollingUpdate
  template:
    metadata:
      annotations:
        verrazzano.io/metricsEnabled: "true"
        verrazzano.io/metricsPath: /metrics
        verrazzano.io/metricsPort: "8080"
      labels:
        app: hello-helidon
        verrazzanohelidonworkloads.oam.verrazzano.io: d58cca68-b131-47e2-8ea4-3923bff38efa
        version: v1
    spec:
      containers:
      - image: ghcr.io/verrazzano/example-helidon-greet-app-v1:1.0.0-1-20230126194830-31cd41f
        imagePullPolicy: IfNotPresent
        name: hello-helidon-container
        ports:
        - containerPort: 8080
          name: http
          protocol: TCP
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
      dnsPolicy: ClusterFirst
      restartPolicy: Always
      schedulerName: default-scheduler
      terminationGracePeriodSeconds: 30
```

A Service resource similar to the one below will be created.
```
apiVersion: v1
kind: Service
metadata:
  labels:
    verrazzanohelidonworkloads.oam.verrazzano.io: d58cca68-b131-47e2-8ea4-3923bff38efa
  name: hello-helidon-deployment
  namespace: hello-helidon
spec:
  clusterIP: 10.96.254.206
  clusterIPs:
  - 10.96.254.206
  internalTrafficPolicy: Cluster
  ipFamilies:
  - IPv4
  ipFamilyPolicy: SingleStack
  ports:
  - name: hello-helidon-container-8080
    port: 8080
    protocol: TCP
    targetPort: 8080
  selector:
    verrazzanohelidonworkloads.oam.verrazzano.io: d58cca68-b131-47e2-8ea4-3923bff38efa
  type: ClusterIP
```