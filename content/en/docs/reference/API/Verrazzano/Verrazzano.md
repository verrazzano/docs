---
title: Verrazzano Custom Resource Definition
linkTitle: Verrazzano CRD
weight: 2
draft: false
---

The Verrazzano custom resource contains the configuration information for an installation.
Here is a sample Verrazzano custom resource file that uses OCI DNS.  See other examples
[here]( {{< release_source_url path=platform-operator/config/samples >}} ).

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
          emailAddress: emailAddress@example.com
    dns:
      oci:
        ociConfigSecret: oci
        dnsZoneCompartmentOCID: dnsZoneCompartmentOcid
        dnsZoneOCID: dnsZoneOcid
        dnsZoneName: my.dns.zone.name
    ingress:
      type: LoadBalancer

```

## VerrazzanoSpec
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `environmentName` | string | Name of the installation.  This name is part of the endpoint access URLs that are generated. The default value is `default`. | No  
| `profile` | string | The installation profile to select.  Valid values are `prod` (production) and `dev` (development).  The default is `prod`. | No |
| `version` | string | The version to install.  Valid versions can be found [here](https://github.com/verrazzano/verrazzano/releases/).  Defaults to the current version supported by the Verrazzano platform operator. | No |
| `components` | [Components](#components) | The Verrazzano components.  | No  |
| `defaultVolumeSource` | [VolumeSource](https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/volume/) | Defines the type of volume to be used for persistence for all components unless overridden, and can be one of either [EmptyDirVolumeSource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#emptydirvolumesource-v1-core) or [PersistentVolumeClaimVolumeSource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#persistentvolumeclaimvolumesource-v1-core). If [PersistentVolumeClaimVolumeSource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#persistentvolumeclaimvolumesource-v1-core) is declared, then the `claimName` must reference the name of an existing `VolumeClaimSpecTemplate` declared in the `volumeClaimSpecTemplates` section. | No
| `volumeClaimSpecTemplates` | [VolumeClaimSpecTemplate](#volumeclaimspectemplate) | Defines a named set of PVC configurations that can be referenced from components to configure persistent volumes.| No |


## VolumeClaimSpecTemplate
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `metadata` | [ObjectMeta](https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/object-meta/) | Metadata about the PersistentVolumeClaimSpec template.  | No |
| `spec` | [PersistentVolumeClaimSpec](https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/persistent-volume-claim-v1/#PersistentVolumeClaimSpec) | A `PersistentVolumeClaimSpec` template that can be referenced by a Component to override its default storage settings for a profile.  At present, only a subset of the `resources.requests` object are honored depending on the component. | No |  

## Components
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `certManager` | [CertManagerComponent](#certmanager-component) | The cert-manager component configuration.  | No |
| `dns` | [DNSComponent](#dns-component) | The DNS component configuration.  | No |
| `ingress` | [IngressComponent](#ingress-component) | The ingress component configuration. | No |
| `istio` | [IstioComponent](#istio-component) | The Istio component configuration. | No |
| `keycloak` | [KeycloakComponent](#keycloak-component) | The Keycloak component configuration. | No |
| `elasticsearch` | [ElasticsearchComponent](#elasticsearch-component) | The Elasticsearch component configuration. | No |
| `prometheus` | [PrometheusComponent](#prometheus-component) | The Prometheus component configuration. | No |
| `kibana` | [KibanaComponent](#kibana-component) | The Kibana component configuration. | No |
| `grafana` | [GrafanaComponent](#grafana-component) | The Grafana component configuration. | No |

### CertManager Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `certificate` | [Certificate](#certificate) | The certificate configuration. | No |

#### Certificate
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `acme` | [Acme](#acme) | The ACME configuration.  Either `acme` or `ca` must be specified. | No |
| `ca` | [CertificateAuthority](#certificateauthority) | The certificate authority configuration.  Either `acme` or `ca` must be specified. | No |

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
| `wildcard` | [DNS-Wilcard](#dns-wildcard) | Wildcard DNS configuration. This is the default with a domain of `nip.io`. | No |
| `oci` | [DNS-OCI](#dns-oci) | OCI DNS configuration. | No |
| `external` | [DNS-External](#dns-external) | External DNS configuration. | No |

#### DNS Wildcard
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `domain` | string | The type of wildcard DNS domain. For example, `nip.io`, `sslip.io`, and such. |  Yes |

#### DNS OCI
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `ociConfigSecret` | string | Name of the OCI configuration secret.  Generate a secret based on the OCI configuration profile you want to use.  You can specify a profile other than DEFAULT and specify the secret name.  See instructions by running `./install/create_oci_config_secret.sh`.| Yes |
| `dnsZoneCompartmentOCID` | string | The OCI DNS compartment OCID. |  Yes |
| `dnsZoneOCID` | string | The OCI DNS zone OCID. |  Yes |
| `dnsZoneName` | string | Name of OCI DNS zone. |  Yes |

#### DNS External
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `suffix` | string | The suffix for DNS names. |  Yes |

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
| `name` | string | The name of a helm override for a Verrazzano component chart, specified with a `—set` flag on the helm command line, e.g. `helm install --set name=value`. For more information concerning chart overrides see [Customize Ingress](/docs/setup/install/customizing/ingress/) |  Yes |
| `value` | string | The value of a helm override for a Verrazzano component chart, specified with a `—set` flag on the helm command line, e.g. `helm install --set name=value`. Either `value` or `valueList` must be specified. For more information concerning chart overrides see [Customize Ingress](/docs/setup/install/customizing/ingress/)|  No |
| `valueList` | string list | The list of helm override values for a Verrazzano component, each specified with a `—set` flag on the helm command line, e.g. `helm install --set name[0]=<first element of valueList> —set name[1]=<second element of valueList>`. Either `value` or `valueList` must be specified. For more information concerning chart overrides see [Customize Ingress](/docs/setup/install/customizing/ingress/)  |  No |
| `setString` | Boolean | Specifies if the argument requires the helm `--set-string` command line flag to override a chart value, e.g. `helm install --set-string name=value`. |  No |

### Istio Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `istioInstallArgs` | [NameValue](#name-value) list | A list of Istio Helm chart arguments and values to apply during the installation of Istio.  Each argument is specified as either a `name/value` or `name/valueList` pair. | No |

### Fluentd Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `extraVolumeMounts` | [ExtraVolumeMount](#extra-volume-mount) list | A list of host path volume mounts in addition to `/var/log` into the Fluentd DaemonSet. The Fluentd component collects log files in the `/var/log/containers` directory of Kubernetes worker nodes. The `/var/log/containers` directory may contain symbolic links to files located outside the `/var/log` directory. If the host path directory containing the log files is located outside of `/var/log`, the Fluentd DaemonSet must have the volume mount of that directory to collect the logs. | No |

#### Extra Volume Mount
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `source` | string | The source host path. |  Yes |
| `destination` | string | The destination path on the Fluentd Container, defaults to the `source` host path. |  No |
| `readOnly` | Boolean | Specifies if the volume mount is read-only, defaults to `true`. |  No |

### Keycloak Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `enabled` | Boolean | If true, then Keycloak will be installed. | No |
| `keycloakInstallArgs` | [NameValue](#name-value) list | Allows providing custom Helm arguments to install Keycloak.  | No
| `mysql` | [MySQLComponent](#mysql-component) | Contains the MySQL component configuration needed for Keycloak. | No

### MySQL Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `mysqlInstallArgs` | [NameValue](#name-value) list | Allows providing custom Helm arguments to install MySQL for Keycloak.  | No
| `volumeSource` | [VolumeSource](https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/volume/) | Defines the type of volume to be used for persistence for Keycloak/MySQL, and can be one of either [EmptyDirVolumeSource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#emptydirvolumesource-v1-core) or [PersistentVolumeClaimVolumeSource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#persistentvolumeclaimvolumesource-v1-core). If [PersistentVolumeClaimVolumeSource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#persistentvolumeclaimvolumesource-v1-core) is declared, then the `claimName` must reference the name of a `VolumeClaimSpecTemplate` declared in the `volumeClaimSpecTemplates` section. | No

### Elasticsearch Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `enabled` | Boolean | If true, then Elasticsearch will be installed. | No |
| `installArgs` | [NameValue](#name-value) list | A list of Verrazzano Helm chart arguments and values to apply during the installation of the Verrazzano system chart.  Each argument is specified as either a `name/value` or `name/valueList` pair. | No |

### Kibana Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `enabled` | Boolean | If true, then Kibana will be installed. | No |

### Prometheus Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `enabled` | Boolean | If true, then Prometheus will be installed. | No |

### Grafana Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `enabled` | Boolean | If true, then Grafana will be installed. | No |
