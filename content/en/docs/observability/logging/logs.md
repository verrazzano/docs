---
title: "Logging Components in Verrazzano"
description: "Learn about Verrazzano logging components"
weight: 1
draft: false
---

The Verrazzano logging stack consists of Fluentd, OpenSearch, and OpenSearch Dashboards components.

* Fluentd: a log aggregator that collects, processes, and formats logs from Kubernetes clusters.
* OpenSearch: a scalable search and analytics engine for storing Kubernetes logs.
* OpenSearch Dashboards: a visualization layer that provides a user interface to query and visualize collected logs.

As shown in the following diagram, logs written to stdout by a container running on Kubernetes are picked up by the kubelet service running on that node and written to `/var/log/containers`.

![Logging](/docs/images/logging.png)
