---
title: "Create a Kubernetes Deployment and Service"
description: "Use these instructions to create a Kubernetes deployment and service"
weight: 1
draft: false
---

1. Create a namespace for the example application and add labels identifying the namespace as managed by Verrazzano and enabled for Istio.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl create namespace hello-helidon
$ kubectl label namespace hello-helidon verrazzano-managed=true istio-injection=enabled
```
</div>
{{< /clipboard >}}

2. Deploy the Hello Helidon Greet application.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
    description: Hello Helidon application
    version: v1.0.0
  labels:
    app: hello-helidon
  name: hello-helidon-deployment
  namespace: hello-helidon
spec:
  progressDeadlineSeconds: 600
  replicas: 1
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      app: hello-helidon
  strategy:
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25%
    type: RollingUpdate
  template:
    metadata:
      annotations:
        verrazzano.io/metricsEnabled: "true" # This annotation is used in the ServiceMonitor YAML to specify whether metrics are enabled.
        verrazzano.io/metricsPath: /metrics  # This annotation is used in the ServiceMonitor YAML to replace the metrics path.
        verrazzano.io/metricsPort: "8080"    # This annotation is used in the ServiceMonitor YAML to replace the metrics port.
      labels:
        app: hello-helidon # This label is used in the Service YAML in the selector.
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
      terminationGracePeriodSeconds: 30

```
</div>
{{< /clipboard >}}

3. Access the Hello Helidon Greet application inside the Kubernetes cluster.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: v1
kind: Service
metadata:
  labels:
    app: hello-helidon
  name: hello-helidon-deployment
  namespace: hello-helidon
spec:
  ports:
  - name: hello-helidon-container-8080
    port: 8080
    protocol: TCP
    targetPort: 8080
  selector:
    app: hello-helidon
```
</div>
{{< /clipboard >}}
