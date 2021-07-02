---
title: "Components"
weight: 11
description: "Access OAM Components available in Verrazzano"
draft: true
---

OAM Components are reusable component templates that can be used and configured by Verrazzano **Applications**. To access the list of **Components** :
1. From the **Home Page**, select "**Components** under Resources navigation section.
1. The Components are displayed as a list of cards. Each card has following information:
   - Name: Name of the component. This is a link and when clicked navigates to the [Components Details](./componentdetails/) screen.
   - Namespace: Namespace in which the component is available.
   - Workload Type: Type of ***Workload*** created by the component.
   - Cluster: Cluster in which the component is available.
   - Project: Project of the component, in cases the component is a Multi-cluster component.

Pagination controls are present on top and bottom of the list of component cards. The list also supports sorting based on Name, Namespace, Workload Type, Cluster and Project of the components. The filter controls below Resources navigation can be used to filter the list of cards based on Project and Cluster of the component.

To know more about Components supported by Verrazzano see the [Components](../../../../docs/applications/#components) section.