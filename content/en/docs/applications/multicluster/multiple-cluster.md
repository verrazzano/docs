---
title: "Deploy an Application to Multiple Clusters"
linkTitle: Multiple Clusters
description: "Learn how to deploy a Verrazzano application to multiple clusters"
weight: 3
draft: false
---

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

## Try out multicluster Verrazzano

For more information, see the [API Documentation]({{< relref "/docs/reference/" >}}) for the resources described here.

To try out multicluster Verrazzano, see the [Multicluster]({{< relref "/docs/examples/multicluster/" >}}) examples.
