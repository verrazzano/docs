---
title: "Troubleshoot Upgrade Issues"
description: "Solve some common upgrade issues"
weight: 4
draft: false
---

In Verrazzano 1.3 and later, upgrade will continue to run until it succeeds or until you delete the Verrazzano CR.  In previous versions,
upgrade could fail and transition to the `UpgradeFailed` state.  If that happens, and you updated the Verrazzano platform operator to 1.3+,
then the Verrazzano CR will transition to `UpgradePaused`.  To continue with the upgrade, you must change the CR version to the current
version of the Verrazzano platform operator.  The following steps illustrate this scenario:

1. You install Verrazzano 1.1.2.
2. You upgrade to 1.2.0 by changing the Verrazzano CR version field to v1.2.0.
   - For some reason, the upgrade failed and the Verrazzano CR state transitions to `UpgradeFailed`.
3. You update the Verrazzano platform operator to 1.3.0.
   - The Verrazzano CR state transitions to `UpgradePaused`.
4. You change the Verrazzano CR version field to v1.3.0.
   - The Verrazzano CR state transitions to `Upgrading` and stays in that state until it completes, then it transitions to `UpgradeComplete`.  


To see detailed progress of the upgrade, view the logs with the following command.
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

For additional troubleshooting help, see [Analysis Advice]({{< relref "/docs/troubleshooting/diagnostictools/analysisadvice/" >}}).
