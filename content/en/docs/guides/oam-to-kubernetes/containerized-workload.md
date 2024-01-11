---
title: "ContainerizedWorkload"
linkTitle: "ContainerizedWorkload"
description: "Review the Kubernetes objects Verrazzano creates for an OAM ContainerizedWorkload"
weight: 5
draft: false
---

Verrazzano generates the following Kubernetes objects for a [ContainerizedWorkload](https://pkg.go.dev/github.com/crossplane/oam-kubernetes-runtime/apis/core/v1alpha2#ContainerizedWorkload):
* apps/v1/Deployment

For example, the following ContainerizedWorkload is defined for the component, `springboot-component`, of the [Spring Boot]({{< relref "/docs/examples/microservices/spring-boot.md" >}}) example.
```
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: springboot-component
spec:
  workload:
    apiVersion: core.oam.dev/v1alpha2
    kind: ContainerizedWorkload
    metadata:
      name: springboot-workload
      labels:
        app: springboot
        version: v1
    spec:
      containers:
      - name: springboot-container
        image: "ghcr.io/verrazzano/example-springboot:1.0.0-1-20230126194830-31cd41f"
        ports:
          - containerPort: 8080
            name: springboot
```

A Deployment object, similar to the following one, will be created.
```
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
    deployment.kubernetes.io/revision: "1"
    description: Spring Boot application
    version: v1.0.0
  labels:
    app: springboot
    version: v1
  name: springboot-workload
  namespace: springboot
spec:
  progressDeadlineSeconds: 600
  replicas: 1
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      containerizedworkload.oam.crossplane.io: 23134b5a-8da9-4224-ba27-965684c692ce
  strategy:
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25%
    type: RollingUpdate
  template:
    metadata:
      creationTimestamp: null
      labels:
        app: springboot
        containerizedworkload.oam.crossplane.io: 23134b5a-8da9-4224-ba27-965684c692ce
        version: v1
    spec:
      containers:
      - image: ghcr.io/verrazzano/example-springboot:1.0.0-1-20230126194830-31cd41f
        imagePullPolicy: IfNotPresent
        name: springboot-container
        ports:
        - containerPort: 8080
          name: springboot
          protocol: TCP
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
      dnsPolicy: ClusterFirst
      restartPolicy: Always
      schedulerName: default-scheduler
      terminationGracePeriodSeconds: 30
```
