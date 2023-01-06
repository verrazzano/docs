---
title: External DNS Configuration
linkTitle: External DNS Configuration
description: Analysis detected External DNS Configuration issue. 
weight: 5
draft: false
---

### Summary
Analysis detected that there was issue with DNS configuration.
The root cause was that, while configuring dns, credentials has issues. It could be authorization issue or wrongly supplied credentials.
### Steps
* Review the OCI credentials which are being supplied during configuration.
* Check the permission for credentials or instance_principal.

### Related information
* [More information on OCI DNS](https://docs.oracle.com/en-us/iaas/Content/DNS/Concepts/dnszonemanagement.htm)

