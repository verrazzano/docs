---
title: "Verrazzano project"
linkTitle: Verrazzano project
weight: 1
draft: false
---

A _project_ provides a way to group application namespaces that are owned or administered by the same user or
group of users. When creating a project, you can specify the _subjects:_ users, groups and/or service accounts, that are
to be granted access to the namespaces governed by the project. Two types of subjects may be specified:
- Project admins, who have both read and write access to the project's namespaces.
- Project monitors, who have read-only access to the project's namespaces.
