---
title: "Keycloak and SSO"
weight: 3
draft: false
---

Verrazzano can be deployed to a number of different hosted and on-premises Kubernetes environments. Particularly in hosted environments, it may not be possible to choose the authentication providers configured for the Kubernetes API server, and Verrazzano may have no ability to view, manage, or authenticate users.

Verrazzano installs Keycloak to provide a common user store across all Kubernetes environments. The Verrazzano admin user can create and manage user accounts in Keycloak, and Verrazzano can authenticate and authorize Keycloak users.

Also, you can configure Keycloak to delegate authentication to an external user store, such as Active Directory or an LDAP server.

Because Keycloak is not configured as an authentication provider for the Kubernetes API, authenticating Keycloak users to Kubernetes requires the use of a proxy that impersonates Keycloak users when making Kubernetes API requests. For more information about the Verrazzano authentication proxy, see [Verrazzano Proxies]({{< relref "/docs/security/proxies/_index.md" >}}).

Keycloak is also used when authenticating to the Verrazzano Console and the various Verrazzano Monitoring Instance (VMI) logging and metrics consoles. The Verrazzano Console uses the OpenID Connect (OIDC) PKCE flow to authenticate users against Keycloak and obtain ID and access tokens. Authentication for VMI consoles is provided by the Verrazzano authentication proxy, which also uses PKCE to authenticate users, validates the resulting tokens, and authorizes incoming requests. For more information about the Verrazzano authentication proxy, see [Verrazzano Proxies]({{< relref "/docs/security/proxies/_index.md" >}}).
