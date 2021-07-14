---
title: "Keycloak and SSO"
description: ""
weight: 5
draft: true
---

Verrazzano can be deployed to a number of different hosted and on-premises Kubernetes environemts. Particularly in hosted environments, it may not be possible to choose the authentication providers configured for the Kubernetes API server, and Verrazzano may have no ability to view, manage, or authenticate users.

Verrazzano installs Keycloak to provide a common user store across all Kubernetes environents. The Verrazzano admin user can create and manage user accounts in Keycloak, and Verrazzano can authenticate and authorize Keycloak users.

Because Keycloak is not configured as an authentication provider for the Kubernetes API, authenticating Keycloak users to Kubernetes requires the use of a proxy that impersonates Keycloak users when making Kubernetes API requests. See [Verrazzano Proxies]({{< relref "/docs/security/proxies/proxies.md" >}}) for more information about the Verrazzano API proxy.

Keycloak is also used when authenticating to the Verrazzano console and the various VMI (logging and metrics) consoles. The Verrazzano console uses the OIDC PKCE flow to authenticate users againt Keycloak and obtain ID and access tokens. Authentication for VMI consoles is provided by the Verrazzano OIDC proxy, which also uses PKCE to authenticate users, validate the resulting tokens, and authorize incoming requests. See [Verrazzano Proxies]({{< relref "/docs/security/proxies/proxies.md" >}}) for more information about the Verrazzano OIDC proxy.
