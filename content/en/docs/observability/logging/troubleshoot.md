---
title: "Troubleshoot logging issues"
description: ""
weight: 6
draft: false
aliases:
  - /docs/monitoring/oci-logging/oci-logging
---

If you are not able to view Verrazzano logs in Oracle Cloud Infrastructure Logging, then check the Fluentd container logs in the cluster to see if there are errors.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl logs -n verrazzano-system -l app=fluentd --tail=-1
```

</div>
{{< /clipboard >}}

If you see `not authorized` error messages, then there is likely a problem with the Oracle Cloud Infrastructure Dynamic Group or IAM policy that is preventing the Fluentd plug-in from communicating with the Oracle Cloud Infrastructure API.

To ensure the appropriate permissions are in place, review the Oracle Cloud Infrastructure Logging [required permissions](https://docs.oracle.com/en-us/iaas/Content/Logging/Task/managinglogs.htm#required_permissions_logs_groups) documentation.
