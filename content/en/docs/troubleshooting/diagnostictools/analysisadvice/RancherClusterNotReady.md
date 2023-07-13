---
title: Rancher Cluster Not Ready
linkTitle: Rancher Cluster Not Ready
description: Analysis detected a cluster managed by Rancher that is not ready.
weight: 5
draft: false
---

### Summary
Analysis detected that a cluster managed by Rancher is not ready.  The state of the cluster will display as Active on the home screen when it is available to be manageable via Rancher.

There are interim states (e.g. Provisioning, Waiting) that may be displayed before a cluster becomes Active. The interim states usually show additional information (e.g. Waiting for cluster to be ready).

### Steps
Review the Rancher logs in the `cattle-system` namespace for additional details as to why the cluster is not ready.

### Related information
* [Rancher Troubleshooting](https://ranchermanager.docs.rancher.com/troubleshooting/)
