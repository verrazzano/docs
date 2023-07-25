---
title: Cluster API Resource Not Ready
linkTitle: Cluster API Resource Not Ready
weight: 5
draft: false
---

### Summary
Analysis detected that a Cluster API `cluster.cluster.x-k8s.io` resource was not in a ready state.
A ready cluster resource will have a status with condition types all set to `True`.

### Steps
Review the logs in the `verrazzano-capi` namespace for additional details as to why the cluster resource is
not ready.
