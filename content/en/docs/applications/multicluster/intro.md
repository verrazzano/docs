---
title: "Multicluster Application Deployment"
weight: 1
draft: false
---

Verrazzano may be installed in a multicluster environment, consisting of an _admin_ cluster and optionally, one or more
_managed_ clusters.
- The admin cluster is a central point from which Verrazzano applications in managed clusters can be deployed and monitored.
- Managed clusters are registered with an admin cluster.
- MultiClusterApplicationConfiguration resources are used to target applications to any cluster in a multicluster Verrazzano environment.

The following diagram shows a high-level overview of how multicluster Verrazzano works. For a more
detailed view, see the diagram [here](#detailed-view-of-multicluster-verrazzano).

![](/docs/images/multicluster/MCConceptsHighLevel.png)

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

## Verrazzano multicluster applications

Verrazzano includes a [MultiClusterApplicationConfiguration]({{< relref "/docs/reference/vao-clusters-v1alpha1#clusters.verrazzano.io/v1alpha1.MultiClusterApplicationConfiguration" >}})
resource definition for applications that may be targeted for placement in one or more clusters.

- A MultiClusterApplicationConfiguration is a wrapper for an ApplicationConfiguration, and additionally allows the
  `placement` of the underlying resource to be specified as a list of names of the clusters in which the
  ApplicationConfiguration must be placed.
- MultiClusterApplicationConfiguration resources, along with their associated Component and Secret resources, are
  created in the admin cluster, in a namespace that is part of a VerrazzanoProject, and targeted for `placement`
  in either the local admin cluster or a remote managed cluster.
- A multicluster application is considered part of a VerrazzanoProject if it is in a namespace that is governed
  by that VerrazzanoProject.

## Managed cluster registration
A managed cluster may be registered with an admin cluster using a two-step process:

**Step 1**: Create a [VerrazzanoManagedCluster]({{< relref "/docs/reference/vco-clusters-v1alpha1#clusters.verrazzano.io/v1alpha1.VerrazzanoManagedCluster" >}}) resource in the `verrazzano-mc` namespace of the admin cluster.

**Step 2**: Retrieve the Kubernetes manifest file generated in the VerrazzanoManagedCluster resource and apply it on
the managed cluster to complete the registration.

When a managed cluster is registered, the following will happen:

- After both steps of the registration are complete, the managed cluster begins polling the admin cluster for
  VerrazzanoProject resources and MultiClusterApplicationConfiguration resources, which specify a `placement` in this managed cluster.
    - Any VerrazzanoProject resources placed in this managed cluster are retrieved, and the corresponding namespaces
       and security permissions (RoleBindings) are created in the managed cluster.
    - Any MultiClusterApplicationConfigurations that are placed in this managed cluster, and are in a VerrazzanoProject that is
      also placed in this managed cluster, are retrieved, and created or updated on the managed cluster. The
      underlying ApplicationConfiguration represented by the MultiClusterApplicationConfiguration is unwrapped, and created or updated on the managed
      cluster. The managed cluster namespace of the MultiClusterApplicationConfiguration and its underlying ApplicationConfiguration match
      the admin cluster namespace of the MultiClusterApplicationConfiguration.
    - Any Component and Secret resources referenced by the retrieved MultiClusterApplicationConfigurations, are also retrieved and created on the managed cluster.
- When the managed cluster connects to the admin cluster, it updates the VerrazzanoManagedCluster resource for this
  managed cluster with:
  - The endpoint URL that the admin cluster should use to scrape Prometheus metrics from the managed cluster.
  - The date and time of the most recent successful connection from the managed cluster to the admin cluster.
- For MultiClusterApplicationConfigurations retrieved and unwrapped on a managed cluster, the application logs are
  sent to OpenSearch on the admin cluster, and may be viewed from the Verrazzano-installed OpenSearch Dashboards on the
  admin cluster. Likewise, application metrics will be scraped by the admin cluster and available from
  Verrazzano-installed Prometheus on the admin cluster.


## Detailed view of multicluster Verrazzano

This diagram shows a detailed view of how multicluster Verrazzano works.

![](/docs/images/multicluster/MCConcepts.png)

For more information, see the [API Documentation]({{< relref "/docs/reference/" >}}) for the resources described here.

## Deploy multicluster applications

For an example of how to deploy an application in a multicluster environment, see [Multicluster ToDo List]({{< relref "/docs/examples/multicluster/todo-list/_index.md" >}}).
