---
title: "Kubernetes RBAC"
weight: 4
draft: false
---

Verrazzano uses Kubernetes Role-Based Access Control (RBAC) to protect Verrazzano resources.

Verrazzano includes a set of roles that can be granted to users, enabling access to Verrazzano resources managed by Kubernetes. In addition, Verrazzano creates a number of roles that grant permissions needed by various Verrazzano system components (operators and third-party components).

Verrazzano creates default role bindings during installation and for projects, at project creation or update.

{{< alert title="NOTE" color="primary" >}}
Kubernetes RBAC must be enabled in every cluster to which Verrazzano is deployed or access control will not work. RBAC is enabled by default in most Kubernetes environments.
{{< /alert >}}

## Verrazzano user roles

The following table lists the defined Verrazzano user roles. Each is a ClusterRole intended to be granted directly to users or groups. (In some scenarios, it may be appropriate to grant a user role to a service account.)

| Verrazzano Role | Binding Scope | Description |
| --------------- | ------------- | ----------- |
| verrazzano-admin | Cluster | Manage Verrazzano system components, clusters, and projects. Install and update Verrazzano. |
| verrazzano-monitor | Cluster | View and monitor Verrazzano system components, clusters, and projects. |
| verrazzano-project-admin | Namespace | Deploy and manage applications. |
| verrazzano-project-monitor | Namespace | View and monitor applications. |

## Kubernetes user roles

Verrazzano roles do not include permissions for Kubernetes itself. Instead, it relies on the default user roles provided by Kubernetes. This allows Verrazzano to easily grant the Kubernetes access appropriate to a Verrazzano role, without having to maintain a long list of fine-grained Kubernetes permissions in the Verrazzano roles.

The following table shows the default Kubernetes roles that are granted by default for each Verrazzano role.

| Verrazzano Role | Kubernetes Role | Binding Scope |
| --------------- | --------------- | ------------- |
| verrazzano-admin | admin | Cluster |
| verrazzano-monitor | view | Cluster |
| verrazzano-project-admin | admin | Namespace |
| verrazzano-project-monitor | view | Namespace |

## Default role bindings

Verrazzano creates role bindings for the system and for projects, binding Verrazzano ClusterRoles to one or more Kubernetes Subjects. By default, each role is bound to a Keycloak group, so all Keycloak users who are members of that group will be granted the role.

Also, Verrazzano creates role bindings for the corresponding Kubernetes user roles. The Kubernetes role appropriate for a given Verrazzano role is bound to the same set of Subjects as the corresponding Verrazzano role.

The default bindings can be overridden by specifying one or more Kubernetes Subjects to which the role should be bound. Any valid Subject can be specified (user, group, or service account), but two caveats should be kept in mind:

- It's generally better to grant a role to a group, rather than a specific user, so that roles can be granted (or withdrawn) by editing a user's group memberships, rather than deleting a role binding and creating a new one.
- If you do want to grant a role directly to a specific user, then the user must be specified using its unique ID, not its user name. This is because the authentication proxy impersonates the `sub` (subject) field from the user's token, which contains the ID. Keycloak user IDs are guaranteed to be unique, unlike user names.

### Default system role bindings

Verrazzano creates role bindings for system users during installation. The default role bindings are listed as follows:

| Role | Default Binding Subject |
| ---- | ----------------------- |
| verrazzano-admin | group: verrazzano-admins |
| verrazzano-monitor | group: verrazzano-monitors |

### Default project role bindings

Verrazzano creates role bindings for project users at project creation or update. The default role bindings are listed as follows:

| Role | Default Binding Subject |
| ---- | ----------------------- |
| verrazzano-project-admin | group: verrazzano-project-_<proj_name>_-admins |
| verrazzano-project-monitor | group: verrazzano-project-_<proj_name>_-monitors |

{{< alert title="NOTE" color="primary" >}}
The role bindings for project roles are created automatically, but the project-specific groups that they refer to are not automatically created. You must create those groups using the Keycloak console or API, or specify different binding subjects for the project.
{{< /alert >}}

## Override default role bindings

You can override the default role bindings that are created for system and project roles.

### Override system role bindings

To override the set of subjects that are bound to Verrazzano (and Kubernetes) roles during installation, add the Subjects to the Verrazzano CR you use to install Verrazzano, as shown in the following example:
{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  ...
  security:
    adminSubjects:
    - name: admin-group
      kind: Group
    monitorSubjects:
    - name: view-group
      kind: Group
  ...
```

</div>
{{< /clipboard >}}
You can specify multiple subjects for both admin and monitor roles. You can also specify a subject or subjects for one role, but not the other. If no subjects are specified for a role, then the default binding subjects will be used.

### Override project role bindings

To override the set of subjects that are bound to Verrazzano (and Kubernetes) roles for a project, add the Subjects to the VerrazzanoProject CR for the project, as shown in the following example.

Note that the generated role bindings will be updated if you update the VerrazzanoProject CR and change the subjects specified for either role.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: clusters.verrazzano.io/v1beta1
kind: VerrazzanoProject
metadata:
  name: my-project
spec:
  ...
  security:
    projectAdminSubjects:
    - name: my-project-admin-group
      kind: Group
    projectMonitorSubjects:
    - name: my-project-view-group
      kind: Group
  ...
```

</div>
{{< /clipboard >}}
As with the system role bindings, you can specify multiple subjects for both project-admin and project-monitor roles. You can also specify a subject or subjects for one role, but not the other. If no subjects are specified for a role, then the default binding subjects will be used.
