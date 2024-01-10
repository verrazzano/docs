---
title: "ManualScalerTrait"
linkTitle: "ManualScalerTrait"
description: "Review the Kubernetes resources Verrazzano modifies for an OAM ManualScalerTrait"
weight: 5
draft: false
---

Verrazzano modifies the following Kubernetes resources for a [ManualScalerTrait](https://github.com/oam-dev/spec/blob/v0.2.1/core/traits/manual_scaler_trait.md):
* The `replicas` of a Deployment, StatefulSet, ReplicaSet, or ReplicationController.

For example, the following ManualScalerTrait is defined for the component, `hello-helidon-component`, of the [Hello World Helidon]({{< relref "/docs/examples/hello-helidon/_index.md" >}}) example.
```
apiVersion: core.oam.dev/v1alpha2
kind: ManualScalerTrait
spec:
  replicaCount: 2
```


The following is a snippet of the Deployment resource with the `replicas` value updated.
```
apiVersion: apps/v1
kind: Deployment
.
.
spec:
  progressDeadlineSeconds: 600
  replicas: 2
```
