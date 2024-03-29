---
title: "LoggingTrait"
linkTitle: "LoggingTrait"
description: "Review the Kubernetes objects Verrazzano creates for an OAM LoggingTrait"
weight: 5
draft: false
---

Verrazzano generates the following Kubernetes objects for a [LoggingTrait]({{< relref "/docs/applications/oam/traits/logging/logging.md" >}}):
* v1/ConfigMap - Contains the definition for how to filter log output.
* An additional container and volume definition is added to the Deployment, StatefulSet, ReplicaSet, or ReplicationController of each component.  The container has an image to use for logging and the volume mount of the logging specification.


For example, the following LoggingTrait is defined for the component, `hello-helidon-component`, of the [Hello World Helidon]({{< relref "/docs/examples/hello-helidon/_index.md" >}}) example.

```
apiVersion: core.oam.dev/v1alpha2
kind: ApplicationConfiguration
metadata:
  name: hello-helidon
  annotations:
    version: v1.0.0
    description: "Hello Helidon application"
spec:
  components:
    - componentName: hello-helidon-component
      traits:
        - trait:
            apiVersion: oam.verrazzano.io/v1alpha1
            kind: MetricsTrait
            spec:
              scraper: verrazzano-system/vmi-system-prometheus-0
        - trait:
            apiVersion: oam.verrazzano.io/v1alpha1
            kind: IngressTrait
            metadata:
              name: hello-helidon-ingress
            spec:
              rules:
                - paths:
                    - path: "/greet"
                      pathType: Prefix
        - trait:
            apiVersion: oam.verrazzano.io/v1alpha1
            kind: LoggingTrait
            metadata:
              name: logging-trait
            spec:
              loggingImage: ghcr.io/verrazzano/fluentd-kubernetes-daemonset:v1.12.3-20210517195222-f345ec2
              loggingConfig: |
                  <match fluent.**>
                    @type null
                  </match>
                  <match **>
                  @type stdout
                  </match>
```

A ConfigMap object, similar to the following one, will be created.
```
apiVersion: v1
kind: ConfigMap
data:
  custom.conf: |
    <match fluent.**>
      @type null
    </match>
    <match **>
    @type stdout
    </match>
metadata:
  labels:
    app: hello-helidon
  name: logging-stdout-hello-helidon-deployment-deployment
  namespace: hello-helidon
```

A container, similar to the following one, will be added to the deployment.
```
      containers:
      - env:
        - name: FLUENTD_CONF
          value: custom.conf
        image: ghcr.io/verrazzano/fluentd-kubernetes-daemonset:v1.12.3-20210517195222-f345ec2
        imagePullPolicy: IfNotPresent
        name: logging-stdout
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
        volumeMounts:
        - mountPath: /fluentd/etc/custom.conf
          name: logging-stdout-hello-helidon-deployment-deployment
          readOnly: true
          subPath: custom.conf
```

A volume definition, similar to the following one, will also be added to the deployment.
```
      volumes:
      - configMap:
          defaultMode: 400
          name: logging-stdout-hello-helidon-deployment-deployment
        name: logging-stdout-hello-helidon-deployment-deployment
```
