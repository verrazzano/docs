---
title: "Network Policies"
weight: 11
description: "Network Policies associated with a Multi-Cluster project deployed in Verrazzano"
draft: true
---

A Multi-Cluster project will create Network Policies for all the applications and components deployed by it in all the managed clusters associated with it. To access Network Policies associated with a **Project** deployed in verrazzano :
1. From the **Home Page**, select "**Projects** under Resources navigation section.
1. Click on the link present against Name column on the project card. The project details page will open up in a separate window.
1. Select **Network Policies** from the **Resources** navigation section. 
1. A list of cards with following information is displayed:
   - Name: Name of the network policy.
   - Match Label Selectors: [Label Selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors) for the application pods on which this network policy will be applied.
   - Match Expression Selectors: [matchExpressions](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#resources-that-support-set-based-requirements) for the application pods on which this network policy will be applied.
   - Policy Types: Types of Network Policy i.e. ***Ingress***, ***Egress*** or both.
   - Ingress Rules: Ingress rules defined in the network policy.
   - Egress Rules: Egress rules defined in the network policy.
   - A link to view the ***yaml*** definition of actual Network Policy.