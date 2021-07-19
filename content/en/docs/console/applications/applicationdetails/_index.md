---
title: "Application Details"
weight: 11
description: "Details of an application deployed in Verrazzano"
draft: true
---

To access the details of an **Application** deployed in verrazzano :
1. From the **Home Page**, select "**Applications** under Resources navigation section.
1. Click on the link present against Name column on the application card. The application details page will open up in a separate window.
3. The Application details screen has following information:
   - General Information: This section is represented as a ***Tab*** and displays Name, Namespace, Created On, Status, Cluster and Project of the application. To switch between tabs, just click on the corresponding tab header.
   - Labels: Labels present on the ***ApplicationConfiguration*** resource in Kubernetes.
   - Annotations: Annotations present on the ***ApplicationConfiguration*** resource in Kubernetes.
   
The Application Details screen also displays **Components** associated with the application in **Resources** section.
To know more about Application Configurations supported by Verrazzano see the [Application Configurations]({{< relref "/docs/applications/#application-configurations" >}}) section.