---
title: "Verrazzano Projects"
weight: 4
draft: false
aliases:
  - /docs/concepts/verrazzanoproject
  - /docs/applications/projects
---

A Verrazzano project provides a way to group application namespaces that are owned or administered by the same user or
group of users. When creating a project, you can specify the _subjects:_ users, groups, or service accounts, that are
to be granted access to the namespaces governed by the project. Two types of subjects may be specified:
- Project admins, who have both read and write access to the project's namespaces.
- Project monitors, who have read-only access to the project's namespaces.

### The VerrazzanoProject resource

A VerrazzanoProject [resource]({{< relref "/docs/reference/vao-clusters-v1alpha1#clusters.verrazzano.io/v1alpha1.VerrazzanoProject" >}}) is created by
  a Verrazzano admin user, and specifies the following:

- A list of namespaces that the project governs.
- One or more users, groups, or service accounts that will be granted the `verrazzano-project-admin` role for the
      VerrazzanoProject. Project admins may deploy or delete applications and related resources in the namespaces
      in the project.
- One or more users, groups, or service accounts that will be granted the `verrazzano-project-monitor` role for the
      VerrazzanoProject. Project monitors may view the resources in the namespaces in the project, but not modify
      or delete them.
- A list of network policies to apply to the namespaces in the project.

The creation of a VerrazzanoProject results in:
- The creation of the specified namespaces in the project, if those do not already exist.
- The creation of a Kubernetes RoleBindings in each of the namespaces, to set up the appropriate
  permissions for the project admins and project monitors of the project.
- The creation of the specified network policies for each of the namespaces.
