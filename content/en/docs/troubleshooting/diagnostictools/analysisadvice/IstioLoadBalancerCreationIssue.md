---
title: Istio Ingress Load Balancer Creation Issue  
linkTitle: Istio Ingress Load Balancer Creation Issue
description: Analysis detected Istio Ingress LoadBalancer is not created successfully.
weight: 5
draft: false
---

### Summary
Analysis detected that the Verrazzano installation failed while creating loadbalancer for the Istio Ingress Gateway.

The root cause appears to be that the while creating public loadbalancer there were no public subnet available.
### Steps

Refer to the platform-specific environment setup for your platform [here]({{< relref "/docs/setup/platforms/_index.md" >}}).

### Related information
* [Platform Setup]({{< relref "/docs/setup/platforms/_index.md" >}})
* [Kubernetes Troubleshooting](https://kubernetes.io/docs/tasks/debug/)
