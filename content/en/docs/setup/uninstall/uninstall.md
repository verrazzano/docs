---
title: "Uninstall"
linkTitle: "Uninstall"
description: "How to uninstall Verrazzano"
weight: 6
draft: false
---

To delete a Verrazzano installation, delete the Verrazzano custom resource you used to
install it into your cluster.

**NOTE**: Verrazzano will not delete your applications during uninstall.  You should delete your
applications before uninstalling Verrazzano.  Your applications are not guaranteed to work after
you uninstall Verrazzano, even if you reinstall Verrazzano.  

The following example starts a deletion of a Verrazzano installation in the background, and then
uses the `kubectl logs -f` command to tail the Console output of the pod performing the uninstall:

```
# Get the name of the Verrazzano custom resource
$ MYVZ=$(kubectl  get vz -o jsonpath="{.items[0].metadata.name}")

# Delete the Verrazzano custom resource
$ kubectl delete verrazzano $MYVZ --wait=false
$ kubectl logs -n verrazzano-install \
    -f $(kubectl get pod \
    -n verrazzano-install \
    -l job-name=verrazzano-uninstall-${MYVZ} \
    -o jsonpath="{.items[0].metadata.name}")
```
