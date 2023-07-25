---
title: Rancher Issues
linkTitle: Rancher Issues
weight: 5
draft: false
---

## Summary
Analysis detected that one or more Rancher resources are in a failure state. See the following sections for details:

- [Applications](#applications)
- [Catalogs](#catalogs)
- [Cluster Drivers](#cluster-drivers)
- [Fleet Bundle](#fleet-bundle)
- [Fleet Bundled Deployment](#fleet-bundled-deployment)
- [Fleet Clusters](#fleet-clusters)
- [Fleet Cluster Groups](#fleet-cluster-groups)
- [Fleet Cluster Registration](#fleet-cluster-registration)
- [Fleet Git Repository](#fleet-git-repository)
- [Git Jobs](#git-jobs)
- [Helm Repositories](#helm-repositories)
- [Managed Charts](#managed-charts)
- [Managed Clusters](#managed-clusters)
- [Nodes](#nodes)
- [Provisioning Clusters](#provisioning-clusters)


### Applications
`app.catalog.cattle.io`
<br>
Analysis detected an issue with the deployment of a Helm chart.

### Catalogs
`catalog.management.cattle.io`
<br>
Analysis detected an issue with the configuration of a catalog of application templates.

### Cluster Drivers
`kontainerdriver.management.cattle.io`
<br>
Analysis detected that a KontainerDriver resource was not in a ready state. A ready KontainerDriver resource will have a status with condition types Active, Downloaded, and Installed set to `True`.

### Fleet Bundle
`bundle.fleet.cattle.io`
<br>
Analysis detected an issue with the status of a Fleet bundle. The Fleet bundle resources are automatically created when a [Fleet Git repository](#fleet-git-repository) resource is created.

### Fleet Bundled Deployment
`bundledeployment.fleet.cattle.io`
<br>
Analysis detected an issue with the status of a Fleet bundled deployment.

### Fleet Clusters
`cluster.fleet.cattle.io`
<br>
Analysis detected an issue with the status of a cluster managed with Fleet.

### Fleet Cluster Groups
`clustergroup.fleet.cattle.io`
<br>
Analysis detected an issue with the status of a cluster group managed with Fleet.

### Fleet Cluster Registration
`clusterregistration.fleet.cattle.io`
<br>
Analysis detected an issue with the registration status of a cluster managed with Fleet.

### Fleet Git Repository
`gitrepo.fleet.cattle.io`
<br>
Analysis detected an issue with the configuration of a Git repository for continuous delivery.

### Git Jobs
`gitjob.gitjob.cattle.io`
<br>
Analysis detected an issue with the status of a Kubernetes job that is configured to be launched based on a Git event.

### Helm Repositories
`clusterrepo.catalog.cattle.io`
<br>
Analysis detected that a Helm repository has not successfully downloaded.

### Managed Charts
`managedchart.management.cattle.io`
<br>
Analysis detected an issue with the status of a managed chart.

### Managed Clusters
`cluster.management.cattle.io`
<br>
Analysis detected that a cluster managed by Rancher is not ready. The state of the cluster will display Active on the home screen when it is available to be managed with Rancher.

There are interim states, such as Provisioning and Waiting, that may be displayed before a cluster becomes Active. The interim states typically show additional information, such as Waiting for cluster to be ready.

### Nodes
`node.management.cattle.io`
<br>
Analysis detected that a node within the cluster is not ready.

There are interim states, such as Provisioning and Updating, that may be displayed before a node becomes Active.

### Provisioning Clusters
`cluster.provisioning.cattle.io`
<br>
Analysis detected that a cluster being provisioned by Rancher is not ready. Clusters are provisioned by [cluster drivers](#cluster-drivers). The state of the cluster will display Active on the home screen when it is available to be managed with Rancher.

There are interim states, such as Provisioning and Waiting, that may be displayed before a cluster becomes Active. The interim states typically show additional information, such as Waiting for cluster to be ready.

## Steps
Review the Rancher logs in the `cattle-system` namespace for additional details about why there is a Rancher issue.

## Related information
* [Rancher Troubleshooting](https://ranchermanager.docs.rancher.com/troubleshooting/)
* [Rancher Fleet Troubleshooting](https://fleet.rancher.io/troubleshooting)
