---
title: Insufficient Memory
linkTitle: Insufficient Memory
weight: 5
draft: false
---

### Summary
Analysis detected that there were nodes reporting insufficient memory.

### Steps
1. Review the detailed analysis data to identify the specific nodes involved.
2. Review the nodes to determine why they do not have sufficient memory.

   a. Are the nodes sized correctly for the workload?
      - For the minimum resources required for installing Verrazzano, see the [Prerequisites]({{< relref "/docs/setup/install/prepare/prereqs.md" >}}).
      - Make sure to take into account the resource guidelines of all the applications that you are deploying.

   b. Is something unexpected running on the nodes or consuming more memory than expected?

### Related information
* [Prerequisites]({{< relref "/docs/setup/install/prepare/prereqs.md" >}})
* [Kubernetes Troubleshooting](https://kubernetes.io/docs/tasks/debug/)
