---
title: "Application Security"
description: "Learn about securing applications in Verrazzano"
weight: 10
draft: true
---

Verrazzano does not provide application security as such, but does provide the following:

## Keycloak

Applications can use the Verrazzano Keycloak server as an Identity Provider. Keycloak supports SAML 2.0 and OpenID Connect (OIDC) authentication and authorization flows. Verrazzano does not provide any explicit integrations for applications.

{{< alert title="NOTE" color="warning" >}}
If using Keycloak for application authentication/authorization, create a new realm to contain application users and clients. Do not use the verrazzano-system realm, or the default (Keycloak system) realm. The Keycloak root user account (**keycloakadmin**) has privileges to create realms.
{{< /alert >}}

## Network security

Verrazzano uses Istio to authenticate and authorize incoming network connections for applications. We also provide support for configuring Kubernetes NetworkPolicy on Verrazzano Projects. NetworkPolicy rules control where network connections can be made.

{{< alert title="NOTE" color="warning" >}}
Enforcement of NetworkPolicy requires that a Kubernetes CNI provider, such as Calico, to be configured for the cluster.
{{< /alert >}}

For more information on how Verrazzano secures network traffic, see [Network Security]({{< relref "/docs/networking/security/net-security.md" >}}).
