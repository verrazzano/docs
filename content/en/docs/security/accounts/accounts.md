---
title: "Default User Accounts"
description: "Learn about default user accounts"
weight: 8
draft: true
---

## Default accounts

During installation, Verrazzano generates several default accounts.

| System | Account | Secret | Secret Namespace | Description |
| ------ | ------- | ------ | ---------------- | ----------- |
| Keycloak | keycloakadmin | `keycloak-http` | `keycloak` | Keycloak root user - full administrative privileges for Keycloak. |
| Keycloak | verrazzano | `verrazzano` | `verrazzano-system` | Verrazzano root user - can manage the verrazzano-system realm in Keycloak, including managing users in that realm. This user is a member of the verrazzano-admins group, and has verrazzano-admin role if default role bindings are used. |
| Ranger | admin | `rancher-admin-secret` | `cattle-system` | Rancher root user - full administrative privileges for Rancher. |
