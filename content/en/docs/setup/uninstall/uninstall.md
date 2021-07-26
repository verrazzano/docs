---
title: "Uninstall"
linkTitle: "Uninstall"
description: "How to uninstall Verrazzano"
weight: 3
draft: false
---


To delete a Verrazzano installation, simply delete the Verrazzano custom resource you used to 
install it into your cluster.

The following example starts a delete of a Verrazzano installation in the background, and then 
uses the `kubectl logs -f` command to tail the uninstall log:

```
# Get the name of the Verrazzano custom resource
$ MYVZ=$(kubectl  get vz -o jsonpath="{.items[0].metadata.name}")

# Delete the Verrazzano custom resource
$ kubectl delete verrazzano $MYVZ --wait=false
$ kubectl logs \
    -f $(kubectl get pod \
    -l job-name=verrazzano-uninstall-${MYVZ} \
    -o jsonpath="{.items[0].metadata.name}")
```
