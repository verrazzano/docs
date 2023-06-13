---
title: "Multicluster Monitoring"
description: "Learn about Verrazzano metrics in a multicluster environment"
weight: 3
draft: false
---

Verrazzano federates metrics from managed clusters to the administrator cluster. This ensures that metrics in managed clusters can be queried from the administrator cluster.

If you enable Thanos on the managed clusters, Verrazzano installs the required set of Thanos components on the managed clusters. Then, on the administrator cluster, Verrazzano automatically configures the managed cluster’s Thanos endpoint in Thanos Query. This allows you to query metrics across all clusters from Thanos Query on the administrator cluster.

For Thanos to query metrics from the managed cluster, Thanos must be enabled on both the administrator and managed clusters. If Thanos is disabled on either the administrator or a managed cluster, Prometheus federation is used to scrape metrics from the managed cluster.

When enabling long metric storage in object storage, it is recommended to use a separate bucket for each managed cluster. This provides metric data isolation and improves overall query performance. For more information, see [Thanos]({{< relref "docs/observability/monitoring/configure/thanos.md" >}}).

The following is a representation of metrics collection in a multicluster environment.

![Metrics](/docs/images/multicluster-metrics.png)
