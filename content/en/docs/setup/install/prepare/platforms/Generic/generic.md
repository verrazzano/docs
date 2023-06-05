---
title: Prepare a Generic Kubernetes Cluster
description: Set up a generic Kubernetes cluster for Verrazzano
Weight: 3
draft: false
aliases:
  - /docs/setup/platforms/generic/generic
---

## Prepare for the generic install

Verrazzano requires that your Kubernetes cluster provides an implementation of network load balancers ([Services of type LoadBalancer](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/)) for a production environment. If your generic Kubernetes implementation provides this feature, then you can use a default configuration
of the Verrazzano custom resource with no customizations and follow the [Installation Guide]({{< relref "/docs/setup/install/" >}}).


{{% alert title="NOTE" color="primary" %}}
Remember to not overlap network Classless Inter-Domain Routing (CIDR) blocks when designing and implementing your Kubernetes cluster; proper routing relies on that.
{{% /alert %}}

You can install a load balancer, such as [MetalLB](https://metallb.universe.tf/). This setup requires knowledge of networking both
inside and outside your Kubernetes cluster. This would include specifics of your [Container Network Interface](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/) (CNI) implementation, IP address allocation schemes, and routing that goes beyond the scope of this documentation. For a Kind implementation, see [Install and configure MetalLB]({{< relref "/docs/setup/install/prepare/platforms/kind/kind.md#install-and-configure-metallb" >}}).


It is possible to use a Kubernetes [Service of type NodePort](https://kubernetes.io/docs/concepts/services-networking/service/#nodeport) to test aspects of Verrazzano.
This requires a good working knowledge of networking and has limited use cases.

## Customizations

Verrazzano is highly customizable.  If your Kubernetes implementation requires a custom configuration, see [Customize Verrazzano]({{< relref "/docs/customize" >}}).

## Next steps

To continue, see the [Installation Guide]({{< relref "/docs/setup/install" >}}).
