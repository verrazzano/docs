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
   The following is an example of the output:
   ```shell
   Uninstalling Verrazzano
   Waiting for verrazzano-uninstall-verrazzano to be ready before starting uninstall - 2 seconds

   2022-07-05 20:09:13 UTC Retrieving the access token from Rancher at rancher.default.172.18.0.231.nip.io
   2022-07-05 20:09:14 UTC Updating https://rancher.default.172.18.0.231.nip.io/v3/clusters/local
   2022-07-05 20:09:14 UTC Status: 200
   2022-07-05 20:09:15 UTC Rancher cluster is still in state: removing
   ...
   ```
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
