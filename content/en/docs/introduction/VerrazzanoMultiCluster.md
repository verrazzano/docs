---
title: "Verrazzano in a Multicluster Environment"
weight: 4
draft: false
aliases:
  - /docs/concepts/verrazzanomulticluster
  - /docs/about/verrazzanomulticluster
---
Review the following key concepts to understand multicluster Verrazzano.
- Admin cluster - A Kubernetes cluster that serves as the central management point for deploying and monitoring applications
  in managed clusters.
- Managed clusters - A Kubernetes cluster that has the following characteristics:
  - It is registered with an admin cluster with a unique name.
  - Verrazzano multicluster applications may be deployed to the managed cluster from the admin cluster.
  - Logs and metrics for Verrazzano system components and Verrazzano multicluster applications deployed on the
    managed cluster are viewable from the admin cluster.
- Verrazzano multicluster resources - Custom Kubernetes resources defined by Verrazzano.
  - Each multicluster resource serves as a wrapper for an underlying resource type.
  - A multicluster resource allows the `placement` of the underlying resource to be specified as a list of
  names of the clusters in which the resource must be placed.

For more details, see [here]({{< relref "/docs/applications/multicluster" >}}).

![](/docs/images/multicluster/MCIntro.png)
