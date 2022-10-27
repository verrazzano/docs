---
title: IngressTrait
weight: 2
draft: false
---

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
| `path` | string | If no path is provided, it defaults to forward slash (`/`). |  No |
| `pathType` | string | Path type values are case-sensitive and formatted as follows: <ul><li>`exact`: exact string match</li><li>`prefix`: prefix-based match</li><li>`regex`: regex-based match</li></ul>If the provided ingress path doesn't contain a `pathType`, it defaults to `prefix` if the path is `/` and `exact` otherwise. | No |
| `authorizationPolicy` | [AuthorizationPolicy](#authorizationpolicy) | Defines the set of rules for authorizing a request. | No |

#### IngressDestination
IngressDestination specifies a specific destination host and port for the ingress paths.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `host` | string | Destination host. | No |
| `port` | uint32 | Destination port. | No |
| `httpCookie` | [HttpCookie](#httpcookie) | Session affinity cookie. | No |

{{< alert title="NOTE" color="warning" >}}
If there are multiple ports defined for a service, then the destination port must be specified OR
the service port name must have the prefix `http`.
{{< /alert >}}

#### HttpCookie
HttpCookie specifies a session affinity cookie for an ingress trait.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `name` | string | The name of the HTTP cookie. | No |
| `path` | string | The path of the HTTP cookie. | No |
| `ttl` | uint32 | The lifetime of the HTTP cookie (in seconds). | No |

#### IngressSecurity
IngressSecurity specifies the secret containing the certificate securing the transport for an ingress trait.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `secretName` | string | The name of a secret containing the certificate securing the transport.  The specification of a secret here implies that a certificate was created for specific hosts, as specified in an [IngressRule](#ingressrule). |  Yes |

#### AuthorizationPolicy
AuthorizationPolicy defines the set of rules for authorizing a request.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `rules` | string array | Rules are used to match requests from request principals to specific paths given an optional list of conditions. |  Yes |

#### AuthorizationRule
AuthorizationRule matches requests from a list of request principals that access a specific path subject to a list of conditions.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `from` | [AuthorizationRuleFrom](#authorizationrulefrom) | Specifies the request principals for access to a request. An asterisk (`*`) will match when the value is not empty, for example, if any request principal is found in the request.|  Yes |
| `when` | [AuthorizationRuleCondition](#authorizationrulecondition) | Specifies a list of additional conditions for access to a request. |  No |

#### AuthorizationRuleFrom
Provides a list of request principals.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `requestPrincipals` | string array | Specifies the request principals for access to a request. |  Yes |

#### AuthorizationRuleCondition
Provides additional required attributes for authorization.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `key` | string  | The name of a request attribute. |  Yes |
| `values` | string array  | A list of allowed values for the attribute. |  Yes |
