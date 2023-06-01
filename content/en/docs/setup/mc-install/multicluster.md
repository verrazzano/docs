---
title: "Install Multicluster"
description: "Set up a multicluster Verrazzano environment"
weight: 1
draft: false
aliases:
  - /docs/setup/install/mc-install/multicluster
---

## Prerequisites

- Before you begin, read this document, [Verrazzano in a multicluster environment]({{< relref "/docs/introduction/VerrazzanoMultiCluster.md" >}}).
- To set up a multicluster Verrazzano environment, you will need two or more Kubernetes clusters. One of these clusters
will be *admin* cluster; the others will be *managed* clusters. For instructions on preparing Kubernetes platforms for installing Verrazzano, see [Platform Setup]({{< relref "/docs/setup/install/prepare/platforms/_index.md" >}}).

{{< alert title="NOTE" color="primary" >}}
If Rancher is not enabled, then refer to [Advanced Multicluster Installation]({{< relref "docs/setup/mc-install/advanced-mc-install.md" >}})
because additional steps are required to register a managed cluster.
{{< /alert >}}

The following instructions assume an admin cluster and a single managed cluster. For each additional managed
cluster, simply repeat the managed cluster instructions.

## Install Verrazzano

To install Verrazzano on each Kubernetes cluster, complete the following steps:

1. On one cluster, install Verrazzano using the `dev` or `prod` profile; this will be the *admin* cluster.
2. On the other cluster, install Verrazzano using the `managed-cluster` profile; this will be a managed cluster. The `managed-cluster` profile contains only the components that are required for a managed cluster.
<br>**NOTE**: You also can use the `dev` or `prod` profile.
3. Then, register the managed clusters in a multicluster environment by following a registration method found [here]({{< relref "/docs/setup/mc-install/register/_index.md" >}}).

For detailed instructions on how to install and customize Verrazzano on a Kubernetes cluster using a specific profile,
see the [Installation Guide]({{< relref "/docs/setup/install/" >}}) and [Installation Profiles]({{< relref "/docs/setup/install/perform/profiles.md" >}}).
