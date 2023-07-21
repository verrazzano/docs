---
title: Rancher Issues
linkTitle: Rancher Issues
description: Analysis detected a Rancher issue
weight: 5
draft: false
---

### Summary
Analysis detected that one or more Rancher resources are in a failure state.

### Applications (app.catalog.cattle.io)
Analysis detected an issue with the deployment of a Helm chart.

### Helm Repositories (clusterrepo.catalog.cattle.io)
Analysis detected that a Helm repository has not successfully downloaded.

### Fleet Bundle (bundle.fleet.cattle.io)
Analysis detected an issue with the status of a Fleet bundle. The Fleet bundle resources are automatically created when a [Fleet Git repository](#fleet-git-repository-gitrepofleetcattleio) resource is created.

### Fleet Bundled Deployment (bundledeployment.fleet.cattle.io)
Analysis detected an issue with the status of a Fleet bundled deployment.

### Fleet Clusters (cluster.fleet.cattle.io)
Analysis detected an issue with the status of a cluster managed with Fleet.

### Fleet Cluster Groups (clustergroup.fleet.cattle.io)
Analysis detected an issue with the status of a cluster group managed with Fleet.

### Fleet Cluster Registration (clusterregistration.fleet.cattle.io)
Analysis detected an issue with the registration status of a cluster managed with Fleet.

### Fleet Git Repository (gitrepo.fleet.cattle.io)
Analysis detected an issue with the configuration of a Git repository for continuous delivery.

### Git Jobs (gitjob.gitjob.cattle.io)
Analysis detected an issue with the status of a Kubernetes job that is configured to be launched based on a git event.

### Catalogs (catalog.management.cattle.io)
Analysis detected an issue with the configuration of a catalog of application templates.

### Managed Clusters (cluster.management.cattle.io)
Analysis detected that a cluster managed by Rancher is not ready. The state of the cluster will display Active on the home screen when it is available to be managed with Rancher.

There are interim states, such as Provisioning and Waiting, that may be displayed before a cluster becomes Active. The interim states typically show additional information, such as Waiting for cluster to be ready.

### Cluster Drivers (kontainerdriver.management.cattle.io)
Analysis detected that a KontainerDriver resource was not in a ready state. A ready KontainerDriver resource will have a status with condition types Active, Downloaded, and Installed set to `True`.

### Managed Charts (managedchart.management.cattle.io)
Analysis detected an issue with the status of a managed chart.

### Nodes (node.management.cattle.io)
Analysis detected that a node within the cluster is not ready.

There are interim states, such as Provisioning and Updating, that may be displayed before a node becomes Active.

### Provisioning Clusters (cluster.provisioning.cattle.io)
Analysis detected that a cluster being provisioned by Rancher is not ready. Clusters are provisioned by [cluster drivers]({{< relref "#cluster-drivers-kontainerdrivermanagementcattleio" >}}). The state of the cluster will display Active on the home screen when it is available to be managed with Rancher.

There are interim states, such as Provisioning and Waiting, that may be displayed before a cluster becomes Active. The interim states typically show additional information, such as Waiting for cluster to be ready.

### Steps
Review the Rancher logs in the `cattle-system` namespace for additional details as to why there is a Rancher issue.

### Related information
* [Rancher Troubleshooting](https://ranchermanager.docs.rancher.com/troubleshooting/)
* [Rancher Fleet Troubleshooting](https://fleet.rancher.io/troubleshooting)
