---
title: "Uninstall Verrazzano"
description: ""
weight: 2
draft: false
aliases:
  - /docs/uninstall/uninstall
---

You can uninstall Verrazzano using the [Verrazzano CLI]({{< relref "/docs/setup/install/" >}}) or with [kubectl](https://kubernetes.io/docs/reference/kubectl/kubectl/).

See the following respective sections:
- [Uninstall using the Verrazzano CLI]({{< relref "#uninstall-using-the-verrazzano-cli" >}})
- [Uninstall using kubectl]({{< relref "#uninstall-using-kubectl" >}})

## Uninstall using the Verrazzano CLI

1. Uninstall Verrazzano.
{{< clipboard >}}

 ```shell
  $ vz uninstall
  ```
{{< /clipboard >}}

2. Wait for the uninstall operation to complete.
   The uninstall logs from the Verrazzano platform operator will be streamed to the command window until the uninstall operation has completed or until the default timeout (20m) has been reached.

   The following is an example of the output:
{{< clipboard >}}
   ```shell
   Uninstalling Verrazzano
   2022-11-22T16:31:20.377Z info Reconciling Verrazzano resource default/verrazzano, generation 2, version 1.4.2
   2022-11-22T16:31:20.377Z info Deleting Verrazzano installation
   2022-11-22T16:31:20.418Z info Uninstalling components
   2022-11-22T16:31:20.418Z info Uninstalling Verrazzano default/verrazzano
   ...
   ```
{{< /clipboard >}}

## Uninstall using kubectl

To delete a Verrazzano installation, delete the Verrazzano custom resource you used to
install it into your cluster.

The following example starts a deletion of a Verrazzano installation in the background and then
uses the `kubectl logs -f` command to tail the output of the pod performing the uninstall operation.

1. Get the name of the Verrazzano custom resource.
{{< clipboard >}}

   ```shell
   $ MYVZ=$(kubectl  get vz -o jsonpath="{.items[0].metadata.name}")
   ```
{{< /clipboard >}}
2. Delete the Verrazzano custom resource. After the custom resource is deleted, the Verrazzano platform operator completes the uninstall process by removing all of the Verrazzano-related components and resources, which can take some time.
{{< clipboard >}}

   ```shell
   $ kubectl delete verrazzano $MYVZ
   ```
{{< /clipboard >}}
<br>
To view the logs during deletion, use the following command:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl logs -n verrazzano-install \
    -f $(kubectl get pod \
    -n verrazzano-install \
    -l app=verrazzano-platform-operator \
    -o jsonpath="{.items[0].metadata.name}") | grep '^{.*}$' \
    | jq -r '."@timestamp" as $timestamp | "\($timestamp) \(.level) \(.message)"'
```
</div>
{{< /clipboard >}}


For troubleshooting help, see [Analysis Advice]({{< relref "/docs/troubleshooting/diagnostictools/analysisadvice/" >}}).
