---
title: Istio Ingress Load Balancer Creation Issue  
linkTitle: Istio Ingress Load Balancer Creation Issue
weight: 5
draft: false
---

### Summary
Analysis detected that the Verrazzano installation failed while creating the load balancer for the Istio ingress gateway.

The root cause was that, while creating the public load balancer, there were no public subnets available.
### Steps

Refer to the platform-specific environment setup for your platform [here]({{< relref "/docs/setup/install/prepare/platforms/_index.md" >}}).

### Related information
* [Platform Setup]({{< relref "/docs/setup/install/prepare/platforms/_index.md" >}})
* [Kubernetes Troubleshooting](https://kubernetes.io/docs/tasks/debug/)
