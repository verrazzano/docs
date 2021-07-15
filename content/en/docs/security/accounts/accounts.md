---
title: "Default User Accounts and Certificates"
description: "Learn about default user accounts and certificates"
weight: 8
draft: true
---

## Default Accounts

Verrazzano generates several default accounts at installation time.

| System | Account | Secret | Secret Namespace | Description |
| ------ | ------- | ------ | ---------------- | ----------- |
| Keycloak | keycloakadmin | keycloak-http | keycloak | Keycloak root user - full admin privileges for Keycloak |
| Keycloak | verrazzano | verrazzano | verrazzano-system | Verrazzano root user - can manage the verrazzano-system realm in Keycloak, including managing users in that realm. This user is a member of the verrazzano-admins group, and has verrazzano-admin role if default role bindings are used |
| Ranger | admin | rancher-admin-secret | cattle-system | Rancher root user - full admin privileges for Rancher |
