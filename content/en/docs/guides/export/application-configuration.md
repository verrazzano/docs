---
title: "ApplicationConfiguration"
linkTitle: "ApplicationConfiguration"
description: "An overview of the Kubernetes resources Verrazzano creates for an OAM ApplicationConfiguration"
weight: 5
draft: false
---

Verrazzano will generate the following Kubernetes resources for an [ApplicationConfiguration](https://pkg.go.dev/github.com/crossplane/oam-kubernetes-runtime/apis/core/v1alpha2#ApplicationConfiguration):
* ?

For example, the ApplicationConfiguration below is defined for the [Hello World Helidon]({{< relref "/docs/examples/hello-helidon/_index.md" >}}) example.


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
```
