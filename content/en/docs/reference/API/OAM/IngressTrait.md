---
title: IngressTrait Custom Resource Definition
linkTitle: IngressTrait CRD
weight: 2
draft: false
---
The IngressTrait custom resource contains the configuration of host and path rules for traffic routing to an application.  Here is a sample ApplicationConfiguration that specifies an IngressTrait.  To deploy an example application that demonstrates this IngressTrait, see [Hello World Helidon]({{< relref "/docs/samples/hello-helidon/" >}}).

```
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
            kind: MetricsTrait
            spec:
                scraper: verrazzano-system/vmi-system-prometheus-0
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
```
In the sample configuration, the IngressTrait `hello-helidon-ingress` is set on the `hello-helidon-component` application component and defines an ingress rule that configures a path and path type.  This exposes a route for external access to the application.  Note that because no `hosts` list is given for the [IngressRule](#ingressrule), a DNS host name is automatically generated.  

For example, with the sample application configuration successfully deployed, the application will be accessible with the `path` specified in the IngressTrait and the generated host name.
```
$ HOST=$(kubectl get gateways.networking.istio.io hello-helidon-hello-helidon-appconf-gw -n hello-helidon -o jsonpath={.spec.servers[0].hosts[0]})
$ echo $HOST
hello-helidon-appconf.hello-helidon.11.22.33.44.nip.io

$ curl -sk -X GET https://${HOST}/greet
```
Alternatively, specific host names can be given in an [IngressRule](#ingressrule).  Doing this implies that a secret and certificate have been created for the specific hosts and the secret name has been specified in the associated [IngressSecurity](#ingresssecurity) `secretName` field.

#### IngressTrait

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `oam.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | IngressTrait |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `spec` |  [IngressTraitSpec](#ingresstraitspec) | The desired state of an ingress trait. |  Yes |

#### IngressTraitSpec
IngressTraitSpec specifies the desired state of an ingress trait.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `rules` | [IngressRule](#ingressrule) array | A list of ingress rules to for an ingress trait. | Yes |
| `tls` | [IngressSecurity](#ingresssecurity) | The security parameters for an ingress trait. This is required only if specific hosts are given in an [IngressRule](#ingressrule). | No |

#### IngressRule
IngressRule specifies a rule for an ingress trait.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `hosts` | string array | One or more hosts exposed by the ingress trait.  Wildcard hosts or hosts that are empty are filtered out. If there are no valid hosts provided, then a DNS host name is automatically generated and used. | No |
| `paths` | [IngressPath](#ingresspath) array | The paths to be exposed for an ingress trait. | Yes |
| `destination` | [IngressDestination](#ingressdestination) | The destination host and port for the ingress paths. | No |

#### IngressPath
IngressPath specifies a specific path to be exposed for an ingress trait.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `path` | string | If no path is provided, it defaults to `/`. |  No |
| `pathType` | string | Path type values are case-sensitive and formatted as follows: <ul><li>`exact`: exact string match</li><li>`prefix`: prefix-based match</li><li>`regex`: regex-based match</li></ul>If the provided ingress path doesn't contain a `pathType`, it defaults to `prefix` if the path is `/` and `exact` otherwise. | No |

#### IngressDestination
IngressDestination specifies a specific destination host and port for the ingress paths.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `host` | string | Destination host. | No |
| `port` | uint32 | Destination port. | No |

{{< alert title="NOTE" color="warning" >}}
If there are multiple ports defined for a service, then the destination port must be specified OR
the service port name must have the prefix "http".
{{< /alert >}}

#### IngressSecurity
IngressSecurity specifies the secret containing the certificate securing the transport for an ingress trait.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `secretName` | string | The name of a secret containing the certificate securing the transport.  The specification of a secret here implies that a certificate was created for specific hosts, as specified in an [IngressRule](#ingressrule). |  Yes |
