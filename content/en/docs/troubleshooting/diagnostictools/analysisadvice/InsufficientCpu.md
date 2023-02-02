---
title: Insufficient Cpu
linkTitle: Insufficient Cpu
description: Analysis detected nodes reporting insufficient cpu
weight: 5
draft: false
---

### Summary
Analysis detected that there were nodes reporting insufficient cpu.

### Steps
1. Review the analysis data to identify the specific nodes involved.
2. Review the nodes to determine why they do not have sufficient cpu.

   a. Are the nodes sized correctly for the workload?

      - For the minimum resources required for installing Verrazzano, see the [Installation Guide]({{< relref "/docs/setup/install/installation.md" >}}).
      - Refer to documentation for other applications that you are deploying for resource guidelines and take those into account.

   b. Is something unexpected running on the nodes or consuming more cpu than expected?

### Related information
* [Installation Guide]({{< relref "/docs/setup/install/installation.md" >}})
* [Kubernetes Troubleshooting](https://kubernetes.io/docs/tasks/debug/)
