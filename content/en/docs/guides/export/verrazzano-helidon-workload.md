---
title: "VerrazzanoHelidonWorkload"
linkTitle: "VerrazzanoHelidonWorkload"
description: "An overview of the Kubernetes resources Verrazzano creates for an OAM VerrazzanoHelidonWorkload"
weight: 5
draft: false
---

Verrazzano will generate the following Kubernetes resources for an [VerrazzanoHelidonWorkload]({{< relref "/docs/applications/oam/workloads/helidon/helidon.md" >}}):
* Creates a Deployment

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