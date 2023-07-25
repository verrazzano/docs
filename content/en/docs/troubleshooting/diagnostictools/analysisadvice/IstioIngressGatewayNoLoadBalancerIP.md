---
title: Istio Ingress Gateway No External IP
linkTitle: Istio Ingress Gateway No External IP
weight: 5
draft: false
---

### Summary
Analysis detected that the Verrazzano installation failed while installing the Istio ingress gateway.

The root cause appears to be that the load balancer is either missing or unable to set the external IP address on the Istio ingress gateway service.

### Steps

Refer to the platform-specific environment setup for your platform [here]({{< relref "/docs/setup/install/prepare/platforms/_index.md" >}}).

### Related information
* [Platform Setup]({{< relref "/docs/setup/install/prepare/platforms/_index.md" >}})
* [Kubernetes Troubleshooting](https://kubernetes.io/docs/tasks/debug/)
