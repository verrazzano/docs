---
title: Ingress Controller Oracle Cloud Infrastructure IP Limit Exceeded
linkTitle: Ingress Controller Oracle Cloud Infrastructure IP Limit Exceeded
description: Analysis detected ingress controller Oracle Cloud Infrastructure IP limit exceeded
weight: 5
draft: false
---

### Summary
Analysis detected that the Verrazzano installation failed while installing the Ingress NGINX Controller.

The root cause appears to be that an Oracle Cloud Infrastructure IP non-ephemeral address limit has been reached.

### Steps
1. Review the messages from the supporting details for the exact limit.
2. Refer to the Oracle Cloud Infrastructure documentation related to managing [IP Addresses](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingpublicIPs.htm#overview).

### Related information
* [Public IP Addresses](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingpublicIPs.htm#overview)
