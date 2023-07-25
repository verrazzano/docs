---
title: "Verify Using CLI kubectl"
weight: 2
draft: false
---


{{< clipboard >}}
To verify the Verrazzano installation, you can use `kubectl` to view the status of the Verrazzano resource.  After a successful installation, Verrazzano status should be `InstallComplete`.

```bash
$ kubectl get vz
```
```
# Example response
NAME                 AVAILABLE   STATUS            VERSION
example-verrazzano   23/23       InstallComplete   v{{<verrazzano_development_version>}}
```
{{< /clipboard >}}

For installation troubleshooting help, see [Analysis Advice]({{< relref "/docs/troubleshooting/diagnostictools/analysisadvice/" >}}).

After the installation has completed, you can use the Verrazzano consoles.
For information on how to get the consoles URLs and credentials, see [Access Verrazzano]({{< relref "/docs/setup/access/" >}}).

## Next steps

(Optional) Run the example applications located [here]({{< relref "/docs/examples/_index.md" >}}).
