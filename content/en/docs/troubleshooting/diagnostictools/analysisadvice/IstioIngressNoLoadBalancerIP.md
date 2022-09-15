---
title: Istio Ingress Gateway No External IP
linkTitle: Istio Ingress Gateway No External IP
description: Analysis detected Istio Ingress Gateway is missing an external IP address
weight: 5
draft: false
---

### Summary
Analysis detected that the Verrazzano installation failed while installing the Istio Ingress Gateway.

The root cause appears to be that the load balancer is either missing or unable to set the external IP address on the Istio Ingress Gateway service.

### Steps

Refer to the platform-specific environment setup for your platform [here]({{< relref "/docs/setup/platforms/_index.md" >}}).

### Related information
* [Platform Setup]({{< relref "/docs/setup/platforms/_index.md" >}})
* [Kubernetes Troubleshooting](https://kubernetes.io/docs/tasks/debug/)
