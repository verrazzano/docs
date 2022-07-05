---
title: "Uninstall"
linkTitle: "Uninstall"
description: "How to uninstall Verrazzano"
weight: 5
draft: false
---


To delete a Verrazzano installation, delete the Verrazzano custom resource you used to
install it into your cluster.

You can uninstall Verrazzano using the [Verrazzano CLI]({{< relref "/docs/setup/install/installation.md" >}}) or with [kubectl](https://kubernetes.io/docs/reference/kubectl/kubectl/).
See the following respective sections.

{{< tabs tabTotal="2" >}}
{{< tab tabName="vz" >}}
<br>

1. Uninstall Verrazzano.
    ```shell
    $ vz uninstall
    ```

2. Wait for the uninstall to complete.
   The Verrazzano operator launches a Kubernetes [job](https://kubernetes.io/docs/concepts/workloads/controllers/job/) to delete the Verrazzano installation.  
   The uninstall logs from that job will be streamed to the command window until the uninstall has completed or until the default timeout (20m) has been reached.

{{< /tab >}}
{{< tab tabName="kubectl" >}}
<br>

The following example starts a deletion of a Verrazzano installation in the background and then
uses the `kubectl logs -f` command to tail the output of the pod performing the uninstall.

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
{{< /tab >}}
{{< /tabs >}}
