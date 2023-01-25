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

## Container security

It is recommended that applications attempt to meet the requirements of the Kubernetes `restricted`  [Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/).
This essentially means running the container as a non-root user, with minimal capabilities, and without the ability to
escalate privileges.

Security for containers should be defined

- In the container image itself
- In the Kubernetes Pod and container declarations

### Specify a non-root user in the container image

Unless otherwise specified, all containers run as the root user (UID 0).  Most do not require this level of access, and it is considered a security risk.

It is recommended that the image build explicitly creates an unprivileged non-root user and group and then uses that with the `USER` instruction.

To achieve this, modify the container's image build and use the `USER <UID>` instruction.  For example,

```
# Run as user 1000
USER 1000
```

will make the process within the container run as UID 1000.  Even if there is no entry in `/etc/passwd` matching the UID declared, 
the container will run as the specified UID with minimal privileges.  

If there is no entry in `/etc/passwd` within the container, running `whoami` from the shell will return an error.
However, running the `id` command from the shell will show that the container process is indeed running as the specified ID:

```
# Exec into a pod and examine the user ID of the container process
% kubectl exec -it mypod -- bash
bash-4.2$ whoami
whoami: cannot find name for user ID 1000
bash-4.2$ id
uid=1000 gid=1000 groups=1000
bash-4.2$ 
```


### Specify security settings for the Pod

In the Kubernetes `Pod` specification there is a [Pod SecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#podsecuritycontext-v1-core) 
for defining security at the pod level and a
[Container SecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#securitycontext-v1-core) used
to define security for containers.  Some fields are common between the two security contexts, and others are unique.  See
the API specifications for each for details.  Where there is overlap, settings defined for at the container level override 
settings defined at the pod level.    

By default, all Kubernetes pods run as the root user (UID 0).  The pod and container security contexts can be used to force
containers within a pod to run as a non-root and prevent the container from acquiring escalated privileges.  These will 
override any `USER` setting within the image.

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

The only means for controlling pod security for the `ContainerizedWorkload` type to specify a non-root user utilizing 
the `USER` instruction in the image build as described previously.

The Helidon and Coherence workloads provide the ability to customize pod security settings.  If those are not being used,
it is recommended that [Standard Kubernetes Resources]({{< relref "/docs/samples/standard-kubernetes.md" >}})
are used to define the application workloads.  This is described in "Security for standard Kubernetes resources" section
below. 

## Pod security for applications using standard Kubernetes resources 

Applications can be deployed using standard Kubernetes resources as described in the [Standard Kubernetes Resources]({{< relref "/docs/samples/standard-kubernetes.md" >}})
example.

Security for these resources can be configured as they would normally for any Kubernetes `Deployment` resource.  For example,

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
