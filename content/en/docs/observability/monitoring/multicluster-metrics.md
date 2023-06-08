---
title: "Multicluster Monitoring"
description: "Learn about Verrazzano metrics in a multicluster environment"
weight: 3
draft: false
---

If you enable Thanos on the managed clusters, Verrazzano installs the required set of Thanos components on the managed clusters. Then, on the administrator cluster, Verrazzano automatically configures the managed cluster’s Thanos endpoint in Thanos Query. This allows you to query metrics across all clusters from Thanos Query on the administrator cluster.

If Thanos is disabled on a managed cluster, then Verrazzano uses the Prometheus federation to scrape metrics from the managed cluster.

When enabling long-term metric storage in object storage, it is recommended to use a separate bucket for each managed cluster. This provides metric data isolation and improves overall query performance.

The following is a representation of metrics collection in a multicluster environment.


![Metrics](/docs/images/multicluster-metrics.png)
