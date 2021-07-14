---
title: "Verrazzano Proxies"
description: ""
weight: 7
draft: true
---

Verrazzano provides two proxies that enable authentication and authorization for Keycloak users accessing Verrazzano resources. The proxies are automatically configured and deployed.

## Verrazzano API Proxy

The API proxy is used to authenticate and authorize Keycloak users, then impersonate them to the Kubernetes API, so that Keycloak users can access Kubernetes resources.

The Verrazzano API proxy is used primarily by the Verrazzano console. The console authenticates users against Keycloak, using the PKCE flow, obtains a bearer token, and then sends the token to the API along with the Kubernetes API request. The API proxy validates the token and, if valid, impersonates the user to the Kubernetes API server. This allows the console to execute Kubernetes API calls on behalf of Keycloak users, with Kubernetes enforcing role-based access control (RBAC) based on the impersonated identity.

In multi-cluster scenarios, the console directs all Kubernetes requests to the admin cluster's API proxy. If a request refers to a resource in a different cluster, the API proxy forwards the request, along with the user's authentication token, to the API proxy running in the remote cluster.

## Verrazzano OIDC Proxy

The OIDC proxy provides Single Sign-On (SSO) across the Verrazzano console and the VMI (monitoring and metrics) consoles. The OIDC proxy is deployed as a sidecar in Kubernetes pods that host VMI consoles. When an unauthenticated request is received by the proxy, it executes the OpenID Connect (OIDC) PKCE authentication flow to obtain tokens for the user. If the user is already authenticated to Keycloak (because they have already accessed either the Verrazzano console or another VMI component), Keycloak returns tokens based on the existing user session, and the process is transparent to the user. If not, Keycloak will authenticates the user, establishing a session, before returning tokens.
