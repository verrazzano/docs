---
title: Cluster API (CAPI) Issues
linkTitle: Cluster API Issues
description: Analysis detected a Cluster API issue
weight: 5
draft: false
---

### Summary
Analysis detected that one or more Cluster API (CAPI) resources are in a failure state. See the following sections for details:

- [Cluster Resource Sets](#cluster-resource-sets)
- [Clusters](#clusters)
- [Machine Deployments](#machine-deployments)
- [Machines](#machines)
- [Machine Sets](#machine-sets)
- [OCI Clusters](#oci-clusters)
- [OCI Machines](#oci-machines)
- [OCNE Configs](#ocne-configs)
- [OCNE Control Planes](#ocne-control-planes)

### Cluster Resource Sets
`clusterresourceset.addons.cluster.x-k8s.io`
<br>
Analysis detected an issue applying one or more resources specified with the ClusterResourceSet resource.

### Clusters
`cluster.cluster.x-k8s.io`
<br>
Analysis detected an issue creating or updating a Cluster API cluster.

### Machine Deployments
`machinedeployment.cluster.x-k8s.io`
<br>
Analysis detected an issue with a MachineDeployment resource for a specific cluster. A MachineDeployment orchestrates
deployments over a fleet of MachineSets.

### Machines
`machine.cluster.x-k8s.io`
<br>
Analysis detected an issue with a Machine resource for a specific cluster.  A Machine represents one node in the
workload cluster created.

### Machine Sets
`machineset.cluster.x-k8s.io`
<br>
Analysis detected an issue with a MachineSet resource for a specific cluster.  A MachineSet is an
abstraction over Machines.

### OCI Clusters
`ocicluster.infrastructure.cluster.x-k8s.io`
<br>
Analysis detected an issue with an OCICluster resource for a specific cluster.  An OCICluster resource represents
a workload cluster created in Oracle Cloud Infrastructure.

### OCI Machines
`ocimachine.infrastructure.cluster.x-k8s.io`
<br>
Analysis detected an issue with an OCIMachine resource for a specific cluster.  An OCIMachine resource represents one
node in the workload cluster created in Oracle Cloud Infrastructure.

### OCNE Configs
`ocneconfig.bootstrap.cluster.x-k8s.io`
<br>
Analysis detected an issue with an OCNEConfig resource for a specific cluster.

### OCNE Control Planes
`ocnecontrolplane.controlplane.cluster.x-k8s.io`
<br>
Analysis detected an issue with an OCNEControlPlane resource for a specific cluster.  An OCNEControlPlane resource
represents the configuration for the OCNE Control Plane.

## Related information
* [Cluster API Troubleshooting](../../../troubleshooting-clusterapi)
