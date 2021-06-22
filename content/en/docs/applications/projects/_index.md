---
title: "Projects"
description: "Learn about Verrazzano projects"
weight: 1
draft: false
---
## Overview
A Verrazzano project provides a way to group application namespaces that are owned or administered by the same user or
group of users.

## The VerrazzanoProject resource
- A `VerrazzanoProject` [resource]({{< relref "/docs/reference/api/multicluster/verrazzanoproject.md" >}}) is created by a Verrazzano admin user, and specifies the following:
    - A list of namespaces that the project governs.
    - A user or group that is designated as the `Project Admin` of the VerrazzanoProject. Project admins may deploy
      or delete applications and related resources in the namespaces in the project.
    - A user or group that is designated as `Project Monitor` of the VerrazzanoProject. Project monitors may view
      the resources in the namespaces in the project, but not modify or delete them.
    - A list of network policies to apply to the namespaces in the project.

The creation of a `VerrazzanoProject` results in:
- The creation of the specified namespaces in the project, if those do not already exist.
- The creation of a Kubernetes `RoleBinding` in each of the namespaces, to set up the appropriate
  permissions for the project admins and project monitors of the project.
- The creation of the specified network policies for each of the namespaces.
