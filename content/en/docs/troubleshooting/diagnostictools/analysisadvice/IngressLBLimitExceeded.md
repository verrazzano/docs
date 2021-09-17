---
title: Ingress Controller Load Balancer Service Limit Reached
linkTitle: Ingress Controller Load Balancer Service Limit Reached
description: Analysis detected that the load balancer service limit was exceeded
weight: 5
draft: false
---

### Summary
Analysis detected that the Verrazzano installation failed while installing the NGINX Ingress Controller.

The root cause appears to be that the load balancer service limit has been reached.

### Steps
1. Review the messages from the supporting details for the exact limits, and delete unused load balancers
2. If available, use a different load balancer shape
3. Refer to OCI documentation on [Service Limits](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/servicelimits.htm#)

### Related information
* [Platform Setup]({{< relref "/docs/setup/platforms/_index.md" >}})
* [Kubernetes Troubleshooting](https://kubernetes.io/docs/tasks/debug-application-cluster/troubleshooting/)
* [More information on load balancers](https://docs.oracle.com/en-us/iaas/Content/Balance/Concepts/balanceoverview.htm)