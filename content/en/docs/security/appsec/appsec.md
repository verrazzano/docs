---
title: "Application Security"
description: "Learn about securing applications in Verrazzano"
weight: 1
draft: false
---

Verrazzano provides the following support.

## Keycloak

Applications can use the Verrazzano Keycloak server as an Identity Provider. Keycloak supports SAML 2.0 and OpenID Connect (OIDC) authentication and authorization flows. Verrazzano does not provide any explicit integrations for applications.

{{< alert title="NOTE" color="danger" >}}
If using Keycloak for application authentication and authorization, create a new realm to contain application users and clients. Do not use the verrazzano-system realm, or the default (Keycloak system) realm. The Keycloak root user account (`keycloakadmin`) has privileges to create realms.
{{< /alert >}}

## Network security

Verrazzano uses Istio to authenticate and authorize incoming network connections for applications. Verrazzano also provides support for configuring Kubernetes NetworkPolicy on Verrazzano projects. NetworkPolicy rules control where network connections can be made.

{{< alert title="NOTE" color="danger" >}}
Enforcement of NetworkPolicy requires that a Kubernetes Container Network Interface (CNI) provider, such as Calico, be configured for the cluster.
{{< /alert >}}

For more information on how Verrazzano secures network traffic, see [Network Security]({{< relref "/docs/networking/security/_index.md" >}}).

## Pod security

By default, all containers within a pod run as root (UID `0`) within the container.  Most applications do not require this level of access and
doing so is considered a security risk.

It is recommended that applications attempt to meet the requirements of the Kubernetes `restricted`  [Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/).
This essentially means running the container within a pod as a non-root user with minimal capabilities, and without the ability to
escalate privileges.  Each container image also should define a non-root user identity that the container process will
run, as by default, for added security.

In the Kubernetes `Pod` specification, there is a [Pod SecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/{{<kubernetes_api_version>}}/#podsecuritycontext-v1-core)
for defining security at the pod level and a
[Container SecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/{{<kubernetes_api_version>}}/#securitycontext-v1-core) used
to define security for containers.  Some fields are common between the two security contexts, and others are unique.  For details, see
the API specifications for each.  Where there is overlap, settings defined at the container level override
settings defined at the pod level.

The following sections describe implementing these standards in more detail.

### Specify a non-root user in the container image

Unless otherwise specified, all containers run as the root user.  It is recommended that each container image build explicitly creates
an unprivileged, non-root user and group, and then uses that with the `USER` instruction in the Dockerfile for the container.

To achieve this, modify the container's image build and use the `USER <UID>` instruction.  

For example:

{{< clipboard >}}
<div class="highlight">

```
# Run as user 1000
USER 1000
```
{{< /clipboard >}}
</div>


This will make the process within the container run as UID `1000`.  Even if there is no entry in `/etc/passwd` matching the UID declared,
the container will run as the specified UID with minimal privileges.  

For example, this is illustrated by a running image using the `kubectl run` command with the defaults:

{{< clipboard >}}
<div class="highlight">

```
% kubectl run -it --rm myol --image=ghcr.io/oracle/oraclelinux:7-slim --restart=Never -- bash
If you don't see a command prompt, try pressing enter.
bash-4.2# whoami
root
bash-4.2# id
uid=0(root) gid=0(root) groups=0(root)
bash-4.2#
```
{{< /clipboard >}}
</div>

To run the same image as a non-root user, you can override the default user and group for the container process, as shown:

{{< clipboard >}}
<div class="highlight">

```
% kubectl run -it --rm myol --image=ghcr.io/oracle/oraclelinux:7-slim --restart=Never --overrides='{ "spec": { "securityContext": { "runAsUser": 1000, "runAsGroup": 1000, "runAsNonRoot": true } } }' -- bash
If you don't see a command prompt, try pressing enter.
bash-4.2$
bash-4.2$ whoami
whoami: cannot find name for user ID 1000
bash-4.2$ id
uid=1000 gid=1000 groups=1000
```
{{< /clipboard >}}
</div>

In the second example, the container is running as UID `1000` with a GID of `1000`.  Running `whoami` from within the container returns an error
because `USER 1000` is not defined in `/etc/passwd`, but running the `id` command from the shell shows that the container process
is indeed running as the desired UID (`1000`).

### Specify security settings for the Pod

By default, containers within Kubernetes pods run as the image default user, which in turn defaults to the root user (UID `0`).  

You can use the pod and container `securityContext` fields to force containers within a pod to run as non-root
and prevent the container from acquiring escalated privileges.  These will override any `USER` setting within the image.

{{< clipboard >}}
<div class="highlight">

```
apiVersion: apps/v1
kind: Deployment
spec:
  ...
  template:
    ...
    spec:
      # Define a security context for all containers in the pod
      securityContext:
        runAsGroup: 1000
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: some-container
        ...
        # Define a security context for the container; settings defined here have precedence over the pod securityContext
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          privileged: false
      ...
```
{{< /clipboard >}}
</div>

As mentioned previously, where there is overlap between the pod and container security settings, the settings defined at the container level
override settings defined at the pod level.

## Helidon pod security

The following `YAML` shows how to explicitly specify the pod security context for a Helidon application.  With these settings,
the Helidon application will meet the requirements of the Kubernetes `restricted` [Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/).  

Note that the `runAsUser` 2000 UID does not exist in the container, as described previously.

{{< clipboard >}}
<div class="highlight">

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
{{< /clipboard >}}
</div>

## Pod security for ContainerizedWorkload applications

The only means for controlling pod security for the [ContainerizedWorkload]({{< relref "/docs/applications/#oam-containerizedworkload" >}}) type is to
specify a non-root user, using the `USER` instruction in the container image build, as described in this section, [Specify a non-root user in the container image](#specify-a-non-root-user-in-the-container-image).

## Pod security for applications using standard Kubernetes resources

You can deploy applications using standard Kubernetes resources. You configure security for these resources as you typically would for any Kubernetes `Deployment` resource.  

For example:

{{< clipboard >}}
<div class="highlight">

```
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: example-deployment
spec:
  workload:
    kind: Deployment
    apiVersion: apps/v1
    name: oam-kube-dep
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: oam-kube-app
      template:
        metadata:
          labels:
            app: oam-kube-app
        spec:
          securityContext:
            runAsGroup: 1000
            runAsNonRoot: true
            runAsUser: 1000
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: oam-kube-cnt
              image: hashicorp/http-echo
              args:
                - "-text=hello"
              securityContext:
                allowPrivilegeEscalation: false
                capabilities:
                  drop:
                    - ALL
                privileged: false
```
{{< /clipboard >}}
</div>
