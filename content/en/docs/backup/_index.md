---
title: "Back Up and Restore"
description: ""
weight: 6
draft: false
aliases:
  - /docs/uninstall/backup
---

{{< alert title="NOTE" color="primary" >}}
Premier Support for Oracle Verrazzano Enterprise Container Platform will end on October 31, 2024, as documented at https://www.oracle.com/us/assets/lifetime-support-middleware-069163.pdf. After that date, Oracle Verrazzano will remain in Sustaining Support indefinitely. There will be no further releases, updates, or fixes.
For more details, see My Oracle Support [Note 2794708.1](https://support.oracle.com/epmos/faces/DocumentDisplay?_afrLoop=33881630232591&id=2794708.1).
{{< /alert >}}

The Verrazzano platform comprises a comprehensive set of open source components, linked together to provide a modern, reliable, and secure platform to deploy cloud native applications.
These documents will help you back up and restore data and configurations in Argo CD, Keycloak, OpenSearch, and Rancher.

The backup procedures are independent and you can invoke them in the order of your choice. For most of the backup functionality, these procedures rely on an object store as the back end, such as an OCI object store.
