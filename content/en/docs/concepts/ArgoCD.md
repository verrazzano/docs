---
title: "Argo CD"
linkTitle: Argo CD
weight: 4
draft: false
---
Argo CD is an enterprise grade GitOps Kubernetes deployment tool that uses Git repositories as the source of truth. It can leverage various declarative deployment mechanisms such as Kubernetes manifests, kustomize, ksonnet and HELM. Argo CD is implemented as a Kubernetes controller. It monitors running applications and compares the deployed state against the desired one in Git. Argo CD reports and visualises the differences, while providing facilities to automatically or manually update the live state with the desired target state.
Components can be defined using Kubernetes manifests, created via the `argocd` command line tool or via the UI.

For more information, see [Argo CD documentation](https://argo-cd.readthedocs.io/en/stable/).
