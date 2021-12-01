---
title: Install Failure
linkTitle: Install Failure
description: Analysis detected an installation failure
weight: 5
draft: false
---

### Summary
Analysis detected that the Verrazzano installation has failed, however, it did not isolate the exact reason for the failure.

### Steps

Check the log output of the installation:
```
$ kubectl logs -n verrazzano-install \
    -f $(kubectl get pod \
    -n verrazzano-install \
    -l app=verrazzano-platform-operator \
    -o jsonpath="{.items[0].metadata.name}") | grep '"operation":"install"'
```
Review the analysis data, which can help identify the issue.

### Related information
* [Installation Guide]({{< relref "/docs/setup/install/installation.md" >}})
* [Kubernetes Troubleshooting](https://kubernetes.io/docs/tasks/debug-application-cluster/troubleshooting/)
