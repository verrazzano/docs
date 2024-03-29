---
title: "Upgrade Verrazzano in a Multicluster Environment"
description: ""
weight: 6
draft: false
aliases:
  - /docs/upgrade/multicluster
  - /docs/uninstall/upgrade/multicluster
---

Each cluster of a multicluster environment is upgraded separately. Follow the [Upgrade Verrazzano]({{< relref "/docs/setup/upgrade/perform.md" >}}) instructions, starting with the admin cluster and then for each managed cluster.

## Verify the upgrade of each managed cluster

For each managed cluster, follow the instructions in each of the following sections:

* [Verify that managed cluster registration has completed]({{< relref "/docs/setup/mc-install/verify-install.md#verify-that-managed-cluster-registration-has-completed" >}})
* [Verify that managed cluster metrics are being collected]({{< relref "/docs/setup/mc-install/verify-install.md#verify-that-managed-cluster-metrics-are-being-collected" >}})
* [Verify that managed cluster logs are being collected]({{< relref "/docs/setup/mc-install/verify-install.md#verify-that-managed-cluster-logs-are-being-collected" >}})
