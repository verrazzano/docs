---
title: "Upgrade Verrazzano in a Multicluster Environment"
description: "Upgrade a multicluster Verrazzano environment"
weight: 6
draft: false
aliases:
  - /docs/upgrade/multicluster
  - /docs/uninstall/upgrade/multicluster
---

Each cluster of a multicluster environment is upgraded separately. Start with the admin cluster, and then for each managed cluster, follow the [Upgrade Verrazzano]({{< relref "/docs/setup/upgrade/perform.md" >}}) instructions.

## Verify the upgrade of each managed cluster

For each managed cluster, follow the instructions in each of the following sections:

* [Verify that managed cluster registration has completed]({{< relref "/docs/setup/mc-install/multicluster.md#verify-that-managed-cluster-registration-has-completed" >}})
* [Verify that managed cluster metrics are being collected]({{< relref "/docs/setup/mc-install/multicluster.md#verify-that-managed-cluster-metrics-are-being-collected" >}})
* [Verify that managed cluster logs are being collected]({{< relref "/docs/setup/mc-install/multicluster.md#verify-that-managed-cluster-logs-are-being-collected" >}})
