---
title: "Clusters"
weight: 11
description: "Access Managed Clusters deployed in Verrazzano."
draft: true
---

To access the list of **Clusters** :
1. From the **Home Page**, select "**Clusters** under Resources navigation section.
1. The Managed Clusters are displayed as a list of cards. Each card has following information:
   - Name: Name of the cluster.
   - Namespace: Namespace in which the corresponding ***VerrazzanoManagedCluster**** Kubernetes resource is created.
   - Status: Status of the cluster.
   - Created on: The Timestamp on which the corresponding ***VerrazzanoManagedCluster**** Kubernetes resource was created in Verrazzano.
   - API Url: API Url of the cluster.
   - Project: Project of the application, in cases the application is a Multi-cluster application.

Pagination controls are present on top and bottom of the list of application cards. The list also supports sorting based on Name, Namespace and Status of the clusters.

To know more about Clusters and their usage see the [Multi-Cluster](../../../docs/applications/multicluster/) section.