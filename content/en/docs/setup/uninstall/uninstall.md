---
title: "Uninstall"
linkTitle: "Uninstall"
description: "How to uninstall Verrazzano"
weight: 5
draft: false
---

## Uninstall Considerations
Before uninstalling Verrazzano, you should delete your Verrazzano applications since they may not function properly once uninstall is done.

When you uninstall Verrazzano:
* All of the Verrazzano components are uninstalled
* The CRDs installed by Verrazzano are not deleted
* Any applications that were deployed will still exist, but they may not be functional

## Performing the Uninstall

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
   The uninstall logs from the `Verrazzano Platform Operator` will be streamed to the command window until the uninstall has completed or until the default timeout (20m) has been reached.

   ...
   ```
{{< /tab >}}
{{< tab tabName="kubectl" >}}
<br>

To delete a Verrazzano installation, delete the Verrazzano custom resource you used to
install it into your cluster.

The following example starts a deletion of a Verrazzano installation in the background and then
uses the `kubectl logs -f` command to tail the output of the pod performing the uninstall.

1. Get the name of the Verrazzano custom resource.

   ```shell
   $ MYVZ=$(kubectl  get vz -o jsonpath="{.items[0].metadata.name}")
   ```
2. Delete the Verrazzano custom resource.  Once the delete is done, the Verrazzano uninstall will be complete.

   ```shell
   $ kubectl delete verrazzano $MYVZ 
      ```

3. Wait for the uninstall to complete.
   The uninstall logs from the `Verrazzano Platform Operator` will be streamed to the command window until the uninstall has completed or until the default timeout (20m) has been reached.

   ```
{{< /tab >}}
{{< /tabs >}}
