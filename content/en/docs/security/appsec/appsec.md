---
title: "Application Security"
description: "Learn about securing applications in Verrazzano"
weight: 1
draft: false
---

Verrazzano provides the following support.

## Keycloak

Applications can use the Verrazzano Keycloak server as an Identity Provider. Keycloak supports SAML 2.0 and OpenID Connect (OIDC) authentication and authorization flows. Verrazzano does not provide any explicit integrations for applications.

{{< alert title="NOTE" color="warning" >}}
If using Keycloak for application authentication and authorization, create a new realm to contain application users and clients. Do not use the verrazzano-system realm, or the default (Keycloak system) realm. The Keycloak root user account (`keycloakadmin`) has privileges to create realms.
{{< /alert >}}

## Network security

Verrazzano uses Istio to authenticate and authorize incoming network connections for applications. Verrazzano also provides support for configuring Kubernetes NetworkPolicy on Verrazzano projects. NetworkPolicy rules control where network connections can be made.

{{< alert title="NOTE" color="warning" >}}
Enforcement of NetworkPolicy requires that a Kubernetes Container Network Interface (CNI) provider, such as Calico, be configured for the cluster.
{{< /alert >}}

For more information on how Verrazzano secures network traffic, see [Network Security]({{< relref "/docs/networking/security/net-security.md" >}}).

## Pod security
The Kubernetes pod specification includes configuration that controls container runtime security settings.  There is a pod-level security context, 
along with container-level security contexts.  Some fields are common between the two security contexts, and others are unique.  See the 
details at [Pod SecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#podsecuritycontext-v1-core) and
[Container SecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#securitycontext-v1-core).

By default, all Kubernetes pods are run as root user, UID 0.  There are a few ways that you can specify that the container run as a non-root user.
The first way is to modify the image build and use the `USER <UID>` instruction.  Even if the there is no user account matching the UID, the container
will run as the specified user.  This means that there is no entry in `/etc/passwd`,
so running `whoami` from the shell will return an error, such as `whoami: cannot find name for user ID 2000`.
However, if you run the `id` command from the shell, you will see that the container process is running as the specified ID.
It is better if the image build explicitly creates a user and group, then uses that with the `USER` instruction.

The second way to run as non-root is to update the security context in the Pod spec.  This works even if you don't specify the `USER` instruction during
the image build.  You can specify the UID and GID in either the pod security context or container security context.  The container security context 
has precedence over the pod security context, and both have precedence over the image `USER`.

## Helidon pod security

The following `YAML` shows how to explicitly specify the pod security context for a Helidon application.  With these settings, 
the Helidon application will meet the requirements of the Kubernetes `restricted` [Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/).  

Note that the `runAsUser` 2000 UID does not exist in the container, as described previously.
```
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: hello-helidon-component
spec:
  workload:
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: VerrazzanoHelidonWorkload
    metadata:
      name: hello-helidon-workload
      labels:
        app: hello-helidon
        version: v1
    spec:
      deploymentTemplate:
        metadata:
          name: hello-helidon-deployment
        podSpec:
          securityContext:
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: hello-helidon-container
...
              securityContext:
                runAsNonRoot: true
                runAsGroup: 2000
                runAsUser: 2000
                privileged: false
                allowPrivilegeEscalation: false
                capabilities:
                  drop:
                    - ALL
```
