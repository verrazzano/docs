---
title: Insufficient CPU
linkTitle: Insufficient CPU
description: Analysis detected nodes reporting insufficient CPU
weight: 5
draft: false
---

### Summary
Analysis detected that there were nodes reporting insufficient CPU.

### Steps
1. Review the detailed analysis data to identify the specific nodes involved.
2. Review the nodes to determine why they do not have sufficient CPU.
   a. Are the nodes sized correctly for the workload?
      - For the minimum resources required for installing Verrazzano, see the [Prerequisite Guide]({{< relref "/docs/setup/prereqs.md" >}}).
      - Refer to documentation for other applications that you are deploying for resource guidelines and take those into account.
   b. Is something unexpected running on the nodes or consuming more CPU than expected?

### Related information
* [Prerequisite Guide]({{< relref "/docs/setup/prereqs.md" >}})
* [Kubernetes Troubleshooting](https://kubernetes.io/docs/tasks/debug/)
