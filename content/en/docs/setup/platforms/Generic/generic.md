---
title: Generic Kubernetes
description: Instructions for setting up a generic Kubernetes cluster for Verrazzano
linkTitle: Generic
Weight: 10
draft: false
---

## Prepare for the generic install

If your generic Kubernetes implementation provides a load balancer implementation, then you can use a default configuration of the
Verrazzano custom resource with no customizations, and follow the [Installation Guide]({{< relref "/docs/setup/install/installation.md#install-the-verrazzano-platform-operator" >}}).

Otherwise, you can install a load balancer, such as [MetalLB](https://metallb.universe.tf/). The platform setup page for
KIND clusters has more details on setting up MetalLB [here]({{< relref "/docs/setup/platforms/kind/kind.md#install-and-configure-metallb" >}}).

### Customizations

Verrazzano is highly customizable.  If your Kubernetes implementation requires custom configuration, see [Customizing Installations](../../customizing).

## Next steps

To continue, see the [Installation Guide]({{< relref "/docs/setup/install/installation.md#install-the-verrazzano-platform-operator" >}}).
