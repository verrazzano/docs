---
title: KontainerDriver Resource Not Ready
linkTitle: KontainerDriver Resource Not Ready
description: Analysis detected a KontainerDriver resource that is not in a ready state.
weight: 5
draft: false
---

### Summary
Analysis detected that a Rancher KontainerDriver resource was not in a ready state.
A ready KontainerDriver resource will have a status with condition types Active, Downloaded, and Installed set the `True`.

### Steps
Review the rancher logs in the cattle-system namespace for additional details as to why the KontainerDriver resource is
not ready.
