---
title: "Verrazzano Architecture"
linkTitle: Architecture
weight: 2
draft: false
---

Each Verrazzano installation sits on top of a Kubernetes cluster (that can be hosted on a variety of environments). Verrazzano relies on the Kubernetes API to pull information from the cluster to its components and push instructions from its components down to the cluster. Specifically, Verrazzano uses [custom resources](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/), extensions of the Kubernetes API to configure Kubernetes environments and provide additional functionality.

Because Verrazzano extends Kubernetes, you can continue to use many of the Kubernetes management tools you're already familiar with, such as kubectl and kubeadm.

Each Kubernetes cluster must have both a Container Network Interface (CNI) and a Container Storage Interface (CSI) plugin.

## Inside a Verrazzano installation

Verrazzano consists of many, discrete components. To coordinate between these components, Verrazzano engages the Istio service mesh - an infrastructure layer that manages the flow of information between services. Most Verrazzano components operate from within the Istio service mesh and rely on it to facilitate fast, reliable, and secure communication between them. Istio also provides useful features such as load balancing, traffic control, observability, and more.

Learn more about how Istio handles traffic and network security in Verrazzano at [Networking]({{< relref "/docs/networking/_index.md" >}}).

The components within the service mesh can broadly be organized into the following categories:

* Backup and restore
* Certificate management
* Cluster management
* GitOps
* Identity management
* Observability
* Verrazzano operators

See [Installed Software]({{< relref "/docs/setup/install/prepare/prereqs#installed-software" >}}) for a list of the components included with Verrazzano. Depending on which [installation profile]({{< relref "/docs/setup/install/perform/profiles/_index.md" >}}) you choose to apply, some components are not enabled by default.

One Verrazzano component that does not reside within the service mesh is the Verrazzano platform operator, a custom Kubernetes operator that handles the management of Verrazzano itself - including installation (and uninstallation), upgrades, and troubleshooting. The platform operator also works with the service mesh to synchronize actions between the components and Kubernetes clusters.


## Application deployment

With Verrazzano, you can manage a variety of application types. Depending on their type, applications are deployed from different spaces within the architecture of Verrazzano.

Applications that conform to the [Open Application Model (OAM)]({{< relref "/docs/introduction/verrazzanooam.md" >}}) specification are deployed within the service mesh. Their close proximity to other components allows for significant automation and configuration benefits.

Other application types are deployed in the Kubernetes cluster. They can still use Verrazzano features but may require additional configuration. Whichever application types you use, they'll benefit from Verrazzano's comprehensive management solution.

## Multicluster support

You can use Verrazzano in single and multicluster Kubernetes environments. In a multicluster environment, there is an *admin* cluster, which is the central management point for deploying and monitoring applications, and one or more *managed* clusters, which look to the admin cluster for configurations.

Verrazzano is installed on every cluster; admin clusters are installed with either a `dev` or `prod` profile, while managed clusters use a `managed-cluster` profile which has fewer components enabled by default and requires registration to an admin cluster. See [Installation Profiles]({{< relref "/docs/setup/install/perform/profiles/_index.md" >}}) for details.

After registration, a managed cluster submits logging and metrics data to its admin cluster, and receives configuration instructions in turn, over HTTPS.