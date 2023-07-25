---
title: Image Pull Not Found
linkTitle: Image Pull Not Found
weight: 5
draft: false
---

### Summary
Analysis detected that there were pods which had issues due to failures to pull an image or images where the root cause was that the image was not found.

### Steps
1. Review the analysis data; it enumerates the pods and related messages regarding which images had this issue.
2. Confirm that the image name, digest, and tag are correctly specified.

### Related information
* [Kubernetes Troubleshooting](https://kubernetes.io/docs/tasks/debug/)
