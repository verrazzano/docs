---
title: "Install Multicluster Verrazzano"
description: ""
weight: 1
draft: false
aliases:
  - /docs/setup/install/mc-install/multicluster
  - /docs/setup/install/multicluster
---

## Prerequisites

- Before you begin, read this document, [Verrazzano in a multicluster environment]({{< relref "/docs/introduction/VerrazzanoMultiCluster.md" >}}).
- To set up a multicluster Verrazzano environment, you will need two or more Kubernetes clusters. One of these clusters
will be the *admin* cluster; the others will be *managed* clusters. For instructions on preparing Kubernetes platforms for installing Verrazzano, see [Platform Setup]({{< relref "/docs/setup/install/prepare/platforms/_index.md" >}}).

{{< alert title="NOTE" color="primary" >}}
If Rancher is not enabled, then refer to [Advanced Multicluster Installation]({{< relref "docs/setup/mc-install/advanced-mc-install.md" >}})
because additional steps are required to register a managed cluster.
{{< /alert >}}

The following instructions assume an admin cluster and a single managed cluster. For each additional managed
cluster, simply repeat the managed cluster set up and registration instructions.

## Set up the admin cluster

One of your clusters will be designated as the *admin* cluster. This cluster will serve as the central management point for your *managed* clusters.
On the admin cluster, install Verrazzano using the `dev` or `prod` profile.

For detailed instructions on how to install and customize Verrazzano on a Kubernetes cluster using a specific profile,
see the [Installation Guide]({{< relref "/docs/setup/install/" >}}) and [Installation Profiles]({{< relref "/docs/setup/install/perform/profiles.md" >}}).

## Set up the managed cluster

The second cluster will be a managed cluster. On this cluster, install Verrazzano using the `managed-cluster` profile.
The `managed-cluster` profile contains only the components that are required for a full-featured Verrazzano managed cluster.
<br>**NOTE**: You also can use the `dev` or `prod` profile, which will install components not required for a managed cluster.

For managed cluster configurations that have a smaller footprint than the `managed-cluster` profile, with correspondingly
limited features, see [Minimal managed cluster configurations]({{< relref "#minimal-managed-cluster-configurations" >}}).

## Register the managed cluster

Register the managed clusters in a multicluster environment by following a registration method found [here]({{< relref "/docs/setup/mc-install/register/_index.md" >}}).
After registration is completed, your Verrazzano multicluster environment is ready to use.

## Minimal managed cluster configurations

You can use minimal Verrazzano managed cluster configurations in cases where managed clusters
need to have a smaller footprint, such as in edge clusters. Note that using smaller managed cluster configurations results in
limited multicluster features.

These examples use Verrazzano with `profile: none`, which means that no Verrazzano components are enabled by default, and
then individually enables the specific Verrazzano components needed.  

### Minimum configuration

To install Verrazzano on a managed cluster with the smallest possible configuration and the fewest features, you can use the [`minimal.yaml`]({{< ghlink raw=true path="examples/multicluster/managed-clusters/minimal.yaml" >}})
file.

In this configuration:
- No metrics are collected for the managed cluster.
- You can view and interact with the managed cluster in the Verrazzano Dashboard on the admin cluster.
- If you have enabled the `argoCD` component on the admin cluster, you can use ArgoCD GitOps to distribute applications from the admin cluster to the managed cluster.

### Observability using Prometheus

Use the [`minimal-prometheus.yaml`]({{< ghlink raw=true path="examples/multicluster/managed-clusters/minimal-prometheus.yaml" >}}) file to install Verrazzano on the managed cluster, with the minimum footprint needed to get Prometheus federation of metrics.

In this configuration:
- The features of the minimum configuration will be available.
- Metrics will be collected on the managed cluster.
- Managed cluster metrics will be available in Prometheus on the admin cluster.

### Observability using Thanos

Use the [`minimal-thanos.yaml`]({{< ghlink raw=true path="examples/multicluster/managed-clusters/minimal-thanos.yaml" >}}) file to install Verrazzano on the managed cluster, with the minimum footprint needed to use Thanos to collect metrics.

To use Thanos to get managed cluster metrics, you also must enable Thanos on the admin cluster. For details,
and additional Thanos configuration information, see the documentation on how to enable and configure [Thanos]({{< relref "/docs/observability/monitoring/configure/thanos.md" >}}).

In this configuration:
- The features of the minimum configuration are available.
- Metrics will be collected on the managed cluster.
- Managed cluster metrics will be available in Thanos on the admin cluster.
