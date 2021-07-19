---
title: "Applications"
weight: 11
description: "View Applications deployed in Verrazzano"
draft: true
---

To view the list of **Applications** :
1. From the **Home Page**, select **Applications** under Resources navigation section.
1. The Applications are displayed as a list of cards. Each card has following information:
   - Name: Name of the application. This is a link and when clicked navigates to the [Application Details]({{< relref "/docs/console/applications/applicationdetails" >}}) screen.
   - Namespace: Namespace in which the application is deployed.
   - Status: Status of the application.
   - Created on: The Timestamp on which the application was deployed in Verrazzano.
   - Cluster: Cluster in which the application is deployed.
   - Project: Project of the application, in cases the application is a Multi-cluster application.

Pagination controls are present on top and bottom of the list of application cards. The list also supports sorting based on Name, Namespace, Status, Cluster and Project of the applications. The filter controls below Resources navigation can be used to filter the list of card based on Status, Project and Cluster of the application.

To know more about **Applications** and **Components** supported by Verrazzano see the [Applications]({{< relref "/docs/applications" >}}) page.