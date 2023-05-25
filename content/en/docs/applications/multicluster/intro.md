---
title: "About Multicluster Application Deployment"
linkTitle: About
description: "Learn about application deployment in a multicluster environment"
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
