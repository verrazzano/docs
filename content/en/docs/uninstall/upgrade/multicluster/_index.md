---
title: "Upgrade Multicluster Verrazzano"
description: "Learn how to upgrade a multicluster Verrazzano environment"
weight: 1
draft: false
---

Each cluster of a multicluster environment is upgraded separately. Start with the admin cluster, and then for each managed cluster, follow the [Upgrade Verrazzano]({{< relref "/docs/uninstall/upgrade/_index.md" >}}) instructions.

## Verify the upgrade of each managed cluster

For each managed cluster, follow the instructions in each of the following sections:

* [Verify that managed cluster registration has completed]({{< relref "/docs/setup/install/multicluster.md#verify-that-managed-cluster-registration-has-completed" >}})
* [Verify that managed cluster metrics are being collected]({{< relref "/docs/setup/install/multicluster.md#verify-that-managed-cluster-metrics-are-being-collected" >}})
* [Verify that managed cluster logs are being collected]({{< relref "/docs/setup/install/multicluster.md#verify-that-managed-cluster-logs-are-being-collected" >}})
