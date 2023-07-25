---
title: "Continuous Delivery"
weight: 8
draft: false
aliases:
  - /docs/applications/argo-cd
---
Argo CD is a Kubernetes deployment tool that uses Git repositories as the source of truth. It monitors running applications and compares the deployed state against the desired one in Git. Argo CD lets you visualize the differences and provides methods to automatically or manually update the live state with the desired target state. For more information, see the [Argo CD documentation](https://argo-cd.readthedocs.io/en/stable/).

In a multicluster Verrazzano environment, Argo CD integration depends on Rancher being enabled on the admin cluster. Argo CD connects to managed clusters using the Rancher proxy, to create the required resources for Argo CD cluster registration.
