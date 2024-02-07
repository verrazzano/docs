---
title: "Security"
description: ""
weight: 9
draft: false
---

{{< alert title="NOTE" color="primary" >}}
Premier Support for Oracle Verrazzano Enterprise Container Platform will end on October 31, 2024, as documented at https://www.oracle.com/us/assets/lifetime-support-middleware-069163.pdf. After that date, Oracle Verrazzano will remain in Sustaining Support indefinitely. There will be no further releases, updates, or fixes.
For more details, see My Oracle Support [Note 2794708.1](https://support.oracle.com/epmos/faces/DocumentDisplay?_afrLoop=33881630232591&id=2794708.1).
{{< /alert >}}

Verrazzano supports Kubernetes Role-Based Access Control (RBAC) for Verrazzano resources, and integrates with Keycloak to enable Single Sign-On (SSO) across the Verrazzano Console and the Verrazzano Monitoring Instance (VMI) logging and metrics consoles. Verrazzano provides proxies that enable SSO and Kubernetes API access for Keycloak user accounts.

For information on how Verrazzano secures network traffic, see [Network Security]({{< relref "/docs/networking/security/_index.md" >}}).
