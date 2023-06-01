---
title: IngressTrait
description: "A trait supporting the generation of an ingress for application access"
weight: 4
draft: false
---
The [IngressTrait]({{< relref "/docs/reference/vao-oam-v1alpha1#oam.verrazzano.io/v1alpha1.IngressTrait" >}}) custom resource contains the configuration of host and path rules for traffic routing to an application.  Here is a sample ApplicationConfiguration that specifies an IngressTrait.  To deploy an example application that demonstrates this IngressTrait, see [Hello World Helidon]({{< relref "/docs/examples/hello-helidon/" >}}).

{{< clipboard >}}
<div class="highlight">

    apiVersion: core.oam.dev/v1alpha2
    kind: ApplicationConfiguration
    metadata:
      name: hello-helidon-appconf
      namespace: hello-helidon
      annotations:
        version: v1.0.0
        description: "Hello Helidon application"
    spec:
      components:
        - componentName: hello-helidon-component
          traits:
            - trait:
                apiVersion: oam.verrazzano.io/v1alpha1
                kind: IngressTrait
                metadata:
                  name: hello-helidon-ingress
                spec:
                  rules:
                    - paths:
                        - path: "/greet"
                          pathType: Prefix

</div>
{{< /clipboard >}}

In the sample configuration, the IngressTrait `hello-helidon-ingress` is set on the `hello-helidon-component` application component and defines an ingress rule that configures a path and path type.  This exposes a route for external access to the application.  Note that because no `hosts` list is given for the [IngressRule](#ingressrule), a DNS host name is automatically generated.

For example, with the sample application configuration successfully deployed, the application will be accessible with the `path` specified in the IngressTrait and the generated host name.

{{< clipboard >}}
<div class="highlight">

    $ HOST=$(kubectl get gateways.networking.istio.io hello-helidon-hello-helidon-gw -n hello-helidon -o jsonpath={.spec.servers[0].hosts[0]})
    $ echo $HOST
    hello-helidon-appconf.hello-helidon.11.22.33.44.nip.io

    $ curl -sk -X GET https://${HOST}/greet

</div>
{{< /clipboard >}}

Load balancer session affinity is configured using an HTTP cookie in a destination rule. Here is an updated sample ApplicationConfiguration that includes a destination rule with an HTTP cookie.

{{< clipboard >}}
<div class="highlight">

    apiVersion: core.oam.dev/v1alpha2
    kind: ApplicationConfiguration
    metadata:
      name: hello-helidon-appconf
      namespace: hello-helidon
      annotations:
        version: v1.0.0
        description: "Hello Helidon application"
    spec:
      components:
        - componentName: hello-helidon-component
          traits:
            - trait:
                apiVersion: oam.verrazzano.io/v1alpha1
                kind: IngressTrait
                metadata:
                  name: hello-helidon-ingress
                spec:
                  rules:
                    - paths:
                        - path: "/greet"
                          pathType: Prefix
                    - destination:
                        httpCookie:
                          name: sessioncookie
                          path: "/"
                          ttl: 600

</div>
{{< /clipboard >}}

Additionally, an authorization policy limiting access to specific request principals and optionally predicated on additional conditions, can be specified for a path.  Request for the path will be limited to matching request principals that meet the defined conditions, otherwise the request will be denied.

{{< clipboard >}}
<div class="highlight">

    apiVersion: core.oam.dev/v1alpha2
    kind: ApplicationConfiguration
    metadata:
      name: hello-helidon-appconf
      namespace: hello-helidon
      annotations:
        version: v1.0.0
        description: "Hello Helidon application"
    spec:
      components:
        - componentName: hello-helidon-component
          traits:
            - trait:
                apiVersion: oam.verrazzano.io/v1alpha1
                kind: IngressTrait
                metadata:
                  name: hello-helidon-ingress
                spec:
                  rules:
                    - paths:
                        - path: "/greet"
                          pathType: Prefix
                          authorizationPolicy:
                            rules:
                              - from:
                                  requestPrincipals:
                                    - "*"
                                  when:
                                    - key: request.auth.claims[realm_access][roles]
                                      values:
                                        - "customer"


</div>
{{< /clipboard >}}

Use the following rules related to the host name:

- If you provide a host name, then you have an option to provide a certificate.  If you do not provide a certificate, then Verrazzano generates one for you.
- If you provide a certificate, the TLS secret for that certificate must be in the `istio-system` namespace.
- If you provide a certificate, then you must provide a host name.
- If you do not provide either a host name or a certificate, then Verrazzano generates them for you.
