---
title: Ingress Controller No Load Balancer IP
linkTitle: Ingress Controller No Load Balancer IP
weight: 5
draft: false
---

### Summary
Analysis detected that the Verrazzano installation failed while installing the NGINX Ingress Controller.

The root cause appears to be that the load balancer is either missing or unable to set the ingress IP address on the NGINX Ingress service.

### Steps

Refer to the platform-specific environment setup for your platform [here]({{< relref "/docs/setup/install/prepare/platforms/_index.md" >}}).

### Related information
* [Platform Setup]({{< relref "/docs/setup/install/prepare/platforms/_index.md" >}})
* [Kubernetes Troubleshooting](https://kubernetes.io/docs/tasks/debug/)
