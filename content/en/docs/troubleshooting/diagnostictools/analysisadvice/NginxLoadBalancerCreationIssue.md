---
title: Ingress NGINX Controller Load Balancer Creation Issue
linkTitle: Ingress NGINX Controller Load Balancer Creation Issue
description: Analysis detected Ingress NGINX Controller load balancer was not created successfully
weight: 5
draft: false
---

### Summary
Analysis detected that the Verrazzano installation failed while creating the load balancer for the Ingress NGINX Controller.

The root cause was that, while creating the public load balancer, there were no public subnets available.
### Steps

Refer to the platform-specific environment setup for your platform [here]({{< relref "/docs/setup/install/prepare/platforms/_index.md" >}}).

### Related information
* [Platform Setup]({{< relref "/docs/setup/install/prepare/platforms/_index.md" >}})
* [Kubernetes Troubleshooting](https://kubernetes.io/docs/tasks/debug/)
