---
title: Ingress Controller Invalid Shape
linkTitle: Ingress Controller Invalid Shape
description: Analysis detected an invalid shape for Oracle Cloud Infrastructure Load Balancer
weight: 5
draft: false
---

### Summary
Analysis detected that the Verrazzano installation failed while installing the NGINX Ingress Controller.

The root cause appears to be that Verrazzano custom resource provided an invalid shape for Oracle Cloud Infrastructure Load Balancer.

### Steps
1. Review the messages from the supporting details for the allowed shape for Oracle Cloud Infrastructure Load Balancer.
2. Refer to the Oracle Cloud Infrastructure documentation related to managing [Load Balancer](https://docs.oracle.com/en-us/iaas/Content/Balance/Tasks/managingloadbalancer.htm#console).

### Related information
* [Managing Load Balancer](https://docs.oracle.com/en-us/iaas/Content/Balance/Tasks/managingloadbalancer.htm#console)
* [Customize Load Balancers on OKE](https://docs.oracle.com/en/cloud/iaas/verrazzano/vzdoc/docs/setup/customizing/ociloadbalancerips/)
