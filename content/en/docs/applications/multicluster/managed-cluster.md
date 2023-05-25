---
title: "Deploy an Application to a Managed Cluster"
linkTitle: Managed Cluster
description: "Learn how to deploy a Verrazzano application to a managed cluster"
weight: 1
draft: false
---

## Admin cluster
A Verrazzano admin cluster is a central management point for:
- Deploying and undeploying applications to the managed clusters registered with the admin cluster.
- Viewing logs and metrics for both Verrazzano Components and applications that reside in the managed clusters.

You may register one or more managed clusters with the admin cluster by creating a VerrazzanoManagedCluster
resource in the `verrazzano-mc` namespace of an admin cluster.

**NOTE**: The admin cluster has a fully functional Verrazzano installation. You can locate applications on the admin
cluster as well as on managed clusters.

## Managed clusters
A Verrazzano managed cluster has a minimal footprint of Verrazzano, installed using the `managed-cluster`
installation profile. A managed cluster has the following additional characteristics:
- It is registered with an admin cluster with a unique name.
- Logs for Verrazzano system Components and Verrazzano multicluster applications are sent to
  OpenSearch running on the admin cluster, and are viewable from that cluster.
- A Verrazzano MultiClusterApplicationConfiguration Kubernetes resource, created on the admin cluster, will be retrieved and deployed to a
  managed cluster if all of the following are true:
    - The MultiClusterApplicationConfiguration is in a namespace governed by a VerrazzanoProject.
    - The VerrazzanoProject has a `placement` value that includes this managed cluster.
    - The MultiClusterApplicationConfiguration itself has a `placement` value that includes this managed cluster.

To deploy an example application to a managed cluster, see [here]({{< relref "/docs/examples/microservices/hello-world.md" >}}).
