---
title: "Clusters"
weight: 11
description: "To view the managed clusters registered with the Verrazzano admin cluster"
draft: true
---

On the Home page, under Resources, select **Clusters**.

Managed clusters are displayed with the following information:
   - Name: The name of the cluster.
   - Namespace: The namespace in which the corresponding VerrazzanoManagedCluster Kubernetes resource was created.
   - Status: The status of the cluster.
   - Created on: The timestamp on which the corresponding VerrazzanoManagedCluster Kubernetes resource was created.
   - API URL: The API URL of the cluster.
   - Project: The application Project; in some cases, a multicluster application.

You can sort clusters based on Name, Namespace, and Status.

For more information, see [Multiclusters]({{< relref "/docs/applications/multicluster" >}}).
