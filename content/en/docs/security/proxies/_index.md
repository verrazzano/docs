---
title: "Verrazzano Authentication Proxy"
weight: 5
draft: false
---

Verrazzano provides a proxy that enables authentication and authorization for Keycloak users accessing Verrazzano resources. This proxy is automatically configured and deployed.

## Kubernetes API

The Verrazzano authentication proxy is used to authenticate and authorize Keycloak users, then impersonate them to the Kubernetes API, so that Keycloak users can access Kubernetes resources.

This capability is used primarily by the Verrazzano Console. The Console authenticates users against Keycloak, using the PKCE flow, obtains a bearer token, and then sends the token to the API along with the Kubernetes API request. The API proxy validates the token and, if valid, impersonates the user to the Kubernetes API server. This allows the Console to run Kubernetes API calls on behalf of Keycloak users, with Kubernetes enforcing role-based access control (RBAC) based on the impersonated identity.

In multicluster scenarios, the Console directs all Kubernetes API requests to the admin cluster's authentication proxy. If a request refers to a resource in a different cluster, the authentication proxy forwards the request, along with the user's authentication token, to the authentication proxy running in the remote cluster.

## Single Sign-On (SSO)

The Verrazzano authentication proxy provides SSO across the Verrazzano Console and the Verrazzano Monitoring Instance (VMI) logging and metrics consoles. When an unauthenticated request is received by the proxy, it runs the OIDC PKCE authentication flow to obtain tokens for the user. If the user is already authenticated to Keycloak (because they have already accessed either the Verrazzano Console or another VMI component), Keycloak returns tokens based on the existing user session, and the process is transparent to the user. If not, Keycloak will authenticate the user, establishing a session, before returning tokens.
