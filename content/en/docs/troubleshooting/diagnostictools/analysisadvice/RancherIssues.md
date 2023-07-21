---
title: Rancher Issues
linkTitle: Rancher Issues
description: Analysis detected a Rancher issue
weight: 5
draft: false
---

### Summary
Analysis detected that one or more Rancher resources are in a failure state.

### app.catalog.cattle.io

### Repositories (clusterrepo.catalog.cattle.io)
Analysis detected that a Helm repository has not successfully downloaded.

### bundle.fleet.cattle.io

### bundledeployment.fleet.cattle.io

### cluster.fleet.cattle.io

### clustergroup.fleet.cattle.io

### clusterregistration.fleet.cattle.io

### Git Repository (gitrepo.fleet.cattle.io)
Analysis detected an issue with the configuration of a Git repository under Continuous Delivery.

### Git Job (gitjob.gitjob.cattle.io)
Analysis detected an issue with the status of a Kubernetes job that is configured to be launched based on a Git event.

### catalog.management.cattle.io

### Managed Clusters (cluster.management.cattle.io)
Analysis detected that a cluster managed by Rancher is not ready. The state of the cluster will display Active on the home screen when it is available to be managed with Rancher.

There are interim states, such as Provisioning and Waiting, that may be displayed before a cluster becomes Active. The interim states typically show additional information, such as Waiting for cluster to be ready.

### Cluster Drivers (kontainerdriver.management.cattle.io)
Analysis detected that a KontainerDriver resource was not in a ready state. A ready KontainerDriver resource will have a status with condition types Active, Downloaded, and Installed set to `True`.

### managedchart.management.cattle.io

### node.management.cattle.io

### Provisioning Cluster (cluster.provisioning.cattle.io)
Analysis detected that a cluster being provisioned by Rancher is not ready. Clusters are provisioned by [cluster drivers]({{< relref "#cluster-drivers-kontainerdrivermanagementcattleio" >}}). The state of the cluster will display Active on the home screen when it is available to be managed with Rancher.

There are interim states, such as Provisioning and Waiting, that may be displayed before a cluster becomes Active. The interim states typically show additional information, such as Waiting for cluster to be ready.

### Steps
Review the Rancher logs in the `cattle-system` namespace for additional details as to why there is a Rancher issue.

### Related information
* [Rancher Troubleshooting](https://ranchermanager.docs.rancher.com/troubleshooting/)
