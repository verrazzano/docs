---
title: "Project Details"
weight: 11
description: "Details of a Project deployed in Verrazzano"
draft: false
---

To view the details of an **Project** deployed in verrazzano :
1. From the **Home Page**, select "**Projects** under Resources navigation section.
1. Click on the link present against Name column on the project card. The project details page will open up in a separate window.
3. The Project details screen has following information:
   - General Information: This section is represented as a ***Tab*** and displays Name, Namespace and Created On timestamp of the project. There is also a link (Project Spec) to view the ***yaml*** spec for the project definition. To switch between tabs, just click on the corresponding tab header.
   - Labels: Labels present on the ***VerrazzanoProject*** resource in Kubernetes.
   - Annotations: Annotations present on the ***VerrazzanoProject*** resource in Kubernetes.
   
The Project Details screen also displays **Namespaces**, **Cluster**, **Security** components and **Network Policies** associated with the project in **Resources** section.