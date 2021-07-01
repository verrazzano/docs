---
title: "Uninstall Guide"
linkTitle: "Uninstall"
description: "How to uninstall Verrazzano"
weight: 3
draft: false
---

## Uninstall Verrazzano

To delete a Verrazzano installation:

```
# Get the name of the Verrazzano custom resource
$ kubectl get verrazzano

# Delete the Verrazzano custom resource
$ kubectl delete verrazzano <name of custom resource>
```

To monitor the console log of the uninstall:

```
$ kubectl logs -f $(kubectl get pod -l job-name=verrazzano-uninstall-my-verrazzano -o jsonpath="{.items[0].metadata.name}")
```
