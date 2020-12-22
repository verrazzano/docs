---
title: Verrazzano Custom Resource Definition
linkTitle: Verrazzano Custom Resource Definition
weight: 2
draft: false
---

The Verrazzano custom resource contains the configuration information for an installation.
Here is a sample Verrazzano custom resource file that uses OCI DNS.  See other examples in
`./operator/config/samples`.

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: my-verrazzano
spec:
  environmentName: env
  profile: prod
  components:
    certManager:
      certificate:
        acme:
          provider: letsEncrypt
          emailAddress: emailAddress@domain.com
    dns:
      oci:
        ociConfigSecret: ociConfigSecret
        dnsZoneCompartmentOCID: dnsZoneCompartmentOcid
        dnsZoneOCID: dnsZoneOcid
        dnsZoneName: my.dns.zone.name
    ingress:
      type: LoadBalancer

```

The following table describes the `spec` portion of the Verrazzano custom resource:

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `environmentName` | string | Name of the installation.  This name is part of the endpoint access URLs that are generated. The default value is `default`. | No  
| `profile` | string | The installation profile to select.  Valid values are `prod` (production) and `dev` (development).  The default is `prod`. | No |
| `version` | string | The version to install.  Valid versions can be found [here](https://github.com/verrazzano/verrazzano/releases/).  Defaults to the current version supported by the Verrazzano platform operator. | No |
| `components` | [Components](#Components) | The Verrazzano components.  | No  |


## Components
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `certManager` | [CertManagerComponent](#certmanager-component) | The cert-manager component configuration.  | No |
| `dns` | [DNSComponent](#dns-component) | The DNS component configuration.  | No |
| `ingress` | [IngressComponent](#ingress-component) | The ingress component configuration. | No |
| `istio` | [IstioComponent](#istio-component) | The Istio component configuration. | No |

### CertManager Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `certificate` | [Certificate](#certificate) | The certificate configuration. | No |

#### Certificate
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `acme` | [Acme](#acme) | The ACME configuration.  Either `acme` or `ca` must be specified. | No |
| `ca` | [CertificateAuthority](#CertificateAuthority) | The certificate authority configuration.  Either `acme` or `ca` must be specified. | No |

#### Acme
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `provider` | string | Name of the Acme provider. |  Yes |
| `emailAddress` | string | Email address of the user. |  Yes |

#### CertificateAuthority
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `secretName` | string | The secret name. |  Yes |
| `clusterResourceNamespace` | string | The secrete namespace. |  Yes |

### DNS Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `oci` | [DNS-OCI](#dns-oci) | OCI DNS configuration.  Either `oci` or `external` must be specified. | No |
| `external` | [DNS-External](#dns-external) | External DNS configuration. Either `oci` or `external` must be specified.   | No |

#### DNS OCI
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `ociConfigSecret` | string | Name of the OCI configuration secret.  Generate a secret named `oci-config` based on the OCI configuration profile you want to use.  You can specify a profile other than DEFAULT and a different secret name.  See instructions by running `./install/create_oci_config_secret.sh`.| Yes |
| `dnsZoneCompartmentOCID` | string | The OCI DNS compartment OCID. |  Yes |
| `dnsZoneOCID` | string | The OCI DNS zone OCID. |  Yes |
| `dnsZoneName` | string | Name of OCI DNS zone. |  Yes |

#### DNS External
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `external.suffix` | string | The suffix for DNS names. |  Yes |

### Ingress Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `type` | string | The ingress type.  Valid values are `LoadBalancer` and `NodePort`.  The default value is `LoadBalancer`.  |  Yes |
| `ingressNginxArgs` |  [NameValue](#name-value) list | The list of argument names and values. | No |
| `ports` | [PortConfig](#port-config) list | The list port configurations used by the ingress. | No |

#### Port Config
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `name` | string | The port name.|  No |
| `port` | string | The port value. |  Yes |
| `targetPort` | string | The target port value. The default is same as the port value. |  Yes |
| `protocol` | string | The protocol used by the port.  TCP is the default. |  No |
| `nodePort` | string | The `nodePort` value. |  No |

#### Name Value
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `name` | string | The argument name. |  Yes |
| `value` | string | The argument value. Either `value` or `valueList` must be specifed. |  No |
| `valueList` | string list | The list of argument values. Either `value` or `valueList` must be specified.   |  No |
| `setString` | Boolean | Specifies if the value is a string |  No |

### Istio Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `istioInstallArgs` | [NameValue](#name-value) list | A list of Istio Helm chart arguments and values to apply during the installation of Istio.  Each argument is specified as either a `name/value` or `name/valueList` pair. | No |
