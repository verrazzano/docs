---
title: Verrazzano (v1beta1)
weight: 2
draft: false
---

The Verrazzano custom resource contains the configuration information for an installation.
Here is a sample Verrazzano custom resource file that uses Oracle Cloud Infrastructure DNS.  See other examples
[here]( {{< release_source_url path=platform-operator/config/samples >}} ).

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
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
    ingressNGINX:
      type: LoadBalancer

```

## VerrazzanoSpec
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `environmentName` | string | Name of the installation.  This name is part of the endpoint access URLs that are generated. The default value is `default`. | No  |
| `profile` | string | The installation profile to select.  Valid values are `prod` (production), `dev` (development), and `managed-cluster`.  The default is `prod`. | No |
| `version` | string | The version to install.  Valid versions can be found [here](https://github.com/verrazzano/verrazzano/releases/).  Defaults to the current version supported by the Verrazzano platform operator. | No |
| `components` | [Components](#components) | The Verrazzano components.  | No  |
| `defaultVolumeSource` | [VolumeSource](https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/volume/) | Defines the type of volume to be used for persistence for all components unless overridden, and can be one of either [EmptyDirVolumeSource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#emptydirvolumesource-v1-core) or [PersistentVolumeClaimVolumeSource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#persistentvolumeclaimvolumesource-v1-core). If [PersistentVolumeClaimVolumeSource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#persistentvolumeclaimvolumesource-v1-core) is declared, then the `claimName` must reference the name of an existing `VolumeClaimSpecTemplate` declared in the `volumeClaimSpecTemplates` section. | No |
| `volumeClaimSpecTemplates` | [VolumeClaimSpecTemplate](#volumeclaimspectemplate) | Defines a named set of PVC configurations that can be referenced from components to configure persistent volumes.| No |


## VolumeClaimSpecTemplate
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `metadata` | [ObjectMeta](https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/object-meta/) | Metadata about the PersistentVolumeClaimSpec template.  | No |
| `spec` | [PersistentVolumeClaimSpec](https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/persistent-volume-claim-v1/#PersistentVolumeClaimSpec) | A `PersistentVolumeClaimSpec` template that can be referenced by a Component to override its default storage settings for a profile.  At present, only a subset of the `resources.requests` object are honored depending on the component. | No |  

## Components
| Field                  | Type                                                              | Description                                        | Required |
|------------------------|-------------------------------------------------------------------|----------------------------------------------------|----------|
| `authProxy`            | [AuthProxyComponent](#authproxy-component)                        | The AuthProxy component configuration.             | No       |
| `certManager`          | [CertManagerComponent](#certmanager-component)                    | The cert-manager component configuration.          | No       |
| `dns`                  | [DNSComponent](#dns-component)                                    | The DNS component configuration.                   | No       |
| `ingressNGINX`         | [IngressComponent](#ingress-component)                            | The ingress component configuration.               | No       |
| `istio`                | [IstioComponent](#istio-component)                                | The Istio component configuration.                 | No       |
| `fluentd`              | [FluentdComponent](#fluentd-component)                            | The Fluentd component configuration.               | No       |
| `jaegerOperator`       | [JaegerOperatorComponent](#jaeger-operator-component)             | The Jaeger Operator component configuration.       | No       |
| `keycloak`             | [KeycloakComponent](#keycloak-component)                          | The Keycloak component configuration.              | No       |
| `mySQLOperator`       | [MySQLOperatorComponent](#mysql-operator-component)               | The MySQL Operator component configuration.        | No |
| `opensearch`           | [OpenSearchComponent](#opensearch-component)                      | The OpenSearch component configuration.            | No       |
| `prometheus`           | [PrometheusComponent](#prometheus-component)                      | The Prometheus component configuration.            | No       |
| `opensearchDashboards` | [OpenSearchDashboardsComponent](#opensearch-dashboards-component) | The OpenSearch Dashboards component configuration. | No       |
| `grafana`              | [GrafanaComponent](#grafana-component)                            | The Grafana component configuration.               | No       |
| `kiali`                | [KialiComponent](#kiali-component)                                | The Kiali component configuration.                 | No       |
| `prometheusOperator`   | [PrometheusOperatorComponent](#prometheus-operator-component)     | The Prometheus Operator component configuration.   | No       |
| `prometheusAdapter`    | [PrometheusAdapterComponent](#prometheus-adapter-component)       | The Prometheus Adapter component configuration.    | No       |
| `kubeStateMetrics`     | [KubeStateMetricsComponent](#kube-state-metrics-component)        | The kube-state-metrics component configuration.    | No       |
| `velero`               | [VeleroComponent](#velero-component)                              | The Velero component configuration.                | No       |
| `rancherBackup`        | [RancherBackupComponent](#rancher-backup-component)               | The rancherBackup component configuration.         | No       |

### AuthProxy Component
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `enabled` | Boolean | If true, then AuthProxy will be installed. | No |
| `monitorChanges` | Boolean | If false, then Verrazzano updates will ignore any configuration changes to this component. Defaults to `true`. | No |
| `overrides` | [Overrides](#overrides) list | List of Overrides for the default `values.yaml` file for the component Helm chart. Lower Overrides have precedence over the ones above them. You can find all possible values [here]( {{< release_source_url path=platform-operator/helm_config/charts/verrazzano-authproxy/values.yaml >}} ) and invalid values will be ignored. | No |

### CertManager Component
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `certificate` | [Certificate](#certificate) | The certificate configuration. | No |
| `monitorChanges` | Boolean | If false, then Verrazzano updates will ignore any configuration changes to this component. Defaults to `true`. | No |
| `overrides` | [Overrides](#overrides) list | List of Overrides for the default `values.yaml` file for the component Helm chart. Lower Overrides have precedence over the ones above them. You can find all possible values [here]( {{< release_source_url path=platform-operator/thirdparty/charts/cert-manager/values.yaml  >}} ) and invalid values will be ignored. | No |

#### Certificate
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `acme` | [Acme](#acme) | The ACME configuration.  Either `acme` or `ca` must be specified. | No |
| `ca` | [CertificateAuthority](#certificateauthority) | The certificate authority configuration.  Either `acme` or `ca` must be specified. | No |

#### Acme
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `provider` | string | Name of the Acme provider. |  Yes |
| `emailAddress` | string | Email address of the user. |  Yes |

#### CertificateAuthority
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `secretName` | string | The secret name. |  Yes |
| `clusterResourceNamespace` | string | The secrete namespace. |  Yes |

### DNS Component
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `wildcard` | [DNS-Wilcard](#dns-wildcard) | Wildcard DNS configuration. This is the default with a domain of `nip.io`. | No |
| `oci` | [DNS-OCI](#dns-oci) | Oracle Cloud Infrastructure DNS configuration. | No |
| `external` | [DNS-External](#dns-external) | External DNS configuration. | No |
| `monitorChanges` | Boolean | If false, then Verrazzano updates will ignore any configuration changes to this component. Defaults to `true`. | No |
| `overrides` | [Overrides](#overrides) list | List of Overrides for the default `values.yaml` file for the component Helm chart. Lower Overrides have precedence over the ones above them. You can find all possible values [here]( {{< release_source_url path=platform-operator/thirdparty/charts/external-dns/values.yaml >}} ) and invalid values will be ignored. | No |

#### DNS Wildcard
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `domain` | string | The type of wildcard DNS domain. For example, `nip.io`, `sslip.io`, and such. |  Yes |

#### DNS Oracle Cloud Infrastructure
| Field | Type | Description                                                                                                                                                                                                                                                       | Required |
| --- | --- |-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| `ociConfigSecret` | string | Name of the Oracle Cloud Infrastructure configuration secret.  Generate a secret based on the Oracle Cloud Infrastructure configuration profile you want to use.  You can specify a profile other than DEFAULT and specify the secret name.  See instructions by running `./install/create_oci_config_secret.sh`. | Yes |
| `dnsZoneCompartmentOCID` | string | The Oracle Cloud Infrastructure DNS compartment OCID.                                                                                                                                                                                                                                     |  Yes |
| `dnsZoneOCID` | string | The Oracle Cloud Infrastructure DNS zone OCID.                                                                                                                                                                                                                                            |  Yes |
| `dnsZoneName` | string | Name of Oracle Cloud Infrastructure DNS zone.                                                                                                                                                                                                                                             |  Yes |
| `dnsScope` | string | Scope of the Oracle Cloud Infrastructure DNS zone (`PRIVATE`, `GLOBAL`). If not specified, then defaults to `GLOBAL`.                                                                                                                                                                           | No |
#### DNS External
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `suffix` | string | The suffix for DNS names. |  Yes |

### Ingress NGINX Component
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `type` | string | The ingress type.  Valid values are `LoadBalancer` and `NodePort`.  The default value is `LoadBalancer`. If the ingress type is `NodePort`, a valid and accessible IP address must be specified using the `controller.service.externalIPs` key in [ingressNGINX.overrides](#overrides). For sample usage, see [External Load Balancers]({{< relref "/docs/setup/customizing/externalLBs.md" >}}). | No |
| `ports` | [PortConfig](#port-config) list | The list port configurations used by the ingress. | No |
| `monitorChanges` | Boolean | If false, then Verrazzano updates will ignore any configuration changes to this component. Defaults to `true`. | No |
| `overrides` | [Overrides](#overrides) list | List of Overrides for the default `values.yaml` file for the component Helm chart. Lower Overrides have precedence over the ones above them. You can find all possible values [here]( {{< release_source_url path=platform-operator/thirdparty/charts/ingress-nginx/values.yaml >}} ) and invalid values will be ignored. | No |

#### Port Config
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `name` | string | The port name.|  No |
| `port` | string | The port value. |  Yes |
| `targetPort` | string | The target port value. The default is same as the port value. |  Yes |
| `protocol` | string | The protocol used by the port.  `TCP` is the default. |  No |
| `nodePort` | string | The `nodePort` value. |  No |

#### Name Value
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `name` | string | The name of a Helm override for a Verrazzano component chart, specified with a `set` flag on the Helm command line, for example, `helm install --set name=value`. For more information about chart overrides, see [Customize Ingress](/docs/setup/customizing/ingress/). |  Yes |
| `value` | string | The value of a Helm override for a Verrazzano component chart, specified with a `set` flag on the Helm command line, for example, `helm install --set name=value`. Either `value` or `valueList` must be specified. For more information about chart overrides, see [Customize Ingress](/docs/setup/customizing/ingress/).|  No |
| `valueList` | string list | The list of Helm override values for a Verrazzano component, each specified with a `set` flag on the Helm command line, for example, `helm install --set name[0]=<first element of valueList> —set name[1]=<second element of valueList>`. Either `value` or `valueList` must be specified. For more information about chart overrides, see [Customize Ingress](/docs/setup/customizing/ingress/).  |  No |
| `setString` | Boolean | Specifies if the argument requires the Helm `--set-string` command-line flag to override a chart value, for example, `helm install --set-string name=value`. |  No |

### Istio Component
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `enabled` | Boolean | If true, then Istio will be installed. | No |
| `monitorChanges` | Boolean | If false, then Verrazzano updates will ignore any configuration changes to this component. Defaults to `true`. | No |
| `overrides` | [Overrides](#overrides) list | List of Overrides for default IstioOperator. Lower Overrides have precedence over the ones above them. You can find all possible values [here](https://istio.io/v1.13/docs/reference/config/istio.operator.v1alpha1/#IstioOperatorSpec). Passing through an invalid IstioOperator resource will result in an error. | No |

### Fluentd Component
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `enabled` | Boolean | If true, then Fluentd will be installed. | No |
| `extraVolumeMounts` | [ExtraVolumeMount](#extra-volume-mount) list | A list of host path volume mounts in addition to `/var/log` into the Fluentd DaemonSet. The Fluentd component collects log files in the `/var/log/containers` directory of Kubernetes worker nodes. The `/var/log/containers` directory may contain symbolic links to files located outside the `/var/log` directory. If the host path directory containing the log files is located outside of `/var/log`, the Fluentd DaemonSet must have the volume mount of that directory to collect the logs. | No |
| `opensearchURL` | string | The target OpenSearch URLs.  Specify this option in [this format](https://docs.fluentd.org/output/elasticsearch#hosts-optional).  The default `http://vmi-system-es-ingest-oidc:8775` is the VMI OpenSearch URL. | No |
| `opensearchSecret` | string | The secret containing the credentials for connecting to OpenSearch.  This secret needs to be created in the `verrazzano-install` namespace prior to creating the Verrazzano custom resource.  Specify the OpenSearch login credentials in the `username` and `password` fields in this secret.  Specify the CA for verifying the OpenSearch certificate in the `ca-bundle` field, if applicable.  The default `verrazzano` is the secret for connecting to the VMI OpenSearch. | No |
| `oci` | [OCILoggingConfiguration](#oci-logging-configuration) | The Oracle Cloud Infrastructure Logging configuration. | No |
| `monitorChanges` | Boolean | If false, then Verrazzano updates will ignore any configuration changes to this component. Defaults to `true`. | No |
| `overrides` | [Overrides](#overrides) list | List of Overrides for the default `values.yaml` file for the component Helm chart. Lower Overrides have precedence over the ones above them. You can find all possible values [here]( {{< release_source_url path=platform-operator/helm_config/charts/verrazzano-fluentd/values.yaml >}} ) and invalid values will be ignored. | No |

### Jaeger Operator Component
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `enabled` | Boolean | If true, then Jaeger Operator will be installed. | No |
| `monitorChanges` | Boolean | If false, then Verrazzano updates will ignore any configuration changes to this component. Defaults to `true`. | No |
| `overrides` | [Overrides](#overrides) list | List of Overrides for the default `values.yaml` file for the component Helm chart. Lower Overrides have precedence over the ones above them. You can find all possible values [here]( {{< release_source_url path=platform-operator/thirdparty/charts/jaegertracing/jaeger-operator/values.yaml >}} ) and invalid values will be ignored. | No |

#### Extra Volume Mount
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `source` | string | The source host path. |  Yes |
| `destination` | string | The destination path on the Fluentd Container, defaults to the `source` host path. |  No |
| `readOnly` | Boolean | Specifies if the volume mount is read-only, defaults to `true`. |  No |

#### Oracle Cloud Infrastructure Logging Configuration

| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `systemLogId` | string | The OCID of the Oracle Cloud Infrastructure Log that will collect system logs. | Yes |
| `defaultAppLogId` | string | The OCID of the Oracle Cloud Infrastructure Log that will collect application logs. | Yes |
| `apiSecret` | string | The name of the secret containing the Oracle Cloud Infrastructure API configuration and private key. | No |

### Keycloak Component
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `enabled` | Boolean | If true, then Keycloak will be installed. | No |
| `mysql` | [MySQLComponent](#mysql-component) | Contains the MySQL component configuration needed for Keycloak. | No |
| `monitorChanges` | Boolean | If false, then Verrazzano updates will ignore any configuration changes to this component. Defaults to `true`. | No |
| `overrides` | [Overrides](#overrides) list | List of Overrides for the default `values.yaml` file for the component Helm chart. Lower Overrides have precedence over the ones above them. You can find all possible values [here]( {{< release_source_url path=platform-operator/thirdparty/charts/keycloak/values.yaml >}} ) and invalid values will be ignored. | No |

### MySQL Component
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `volumeSource` | [VolumeSource](https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/volume/) | Defines the type of volume to be used for persistence for Keycloak/MySQL, and can be one of either [EmptyDirVolumeSource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#emptydirvolumesource-v1-core) or [PersistentVolumeClaimVolumeSource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#persistentvolumeclaimvolumesource-v1-core). If [PersistentVolumeClaimVolumeSource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#persistentvolumeclaimvolumesource-v1-core) is declared, then the `claimName` must reference the name of a `VolumeClaimSpecTemplate` declared in the `volumeClaimSpecTemplates` section. | No |
| `monitorChanges` | Boolean | If false, then Verrazzano updates will ignore any configuration changes to this component. Defaults to `true`. | No |
| `overrides` | [Overrides](#overrides) list | List of Overrides for the default `values.yaml` file for the component Helm chart. Lower Overrides have precedence over the ones above them. You can find all possible values [here]( {{< release_source_url path=platform-operator/thirdparty/charts/mysql/values.yaml >}} ) and invalid values will be ignored. | No |

### MySQL Operator Component
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `enabled`   | Boolean | If true, then MySQL Operator will be installed. | No |
| `overrides` | [Overrides](#overrides) list | List of Overrides for the default `values.yaml` file for the component Helm chart. Lower Overrides have precedence over the ones above them. You can find all possible values [here]( {{< release_source_url path=platform-operator/thirdparty/charts/mysql-operator/values.yaml >}} ) and invalid values will be ignored. | No |

### OpenSearch Component
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `enabled` | Boolean | If true, then OpenSearch will be installed. | No |
| `policies` | [Policy](#opensearch-index-management-policies) list | A list of [Index State Management]({{<opensearch_docs_url>}}/im-plugin/ism/index/) policies to enable on OpenSearch. | No |
| `nodes` | [Node](#opensearch-node-groups) list | A list of OpenSearch node groups.  For sample usage, see [Customize OpenSearch](/docs/setup/customizing/opensearch/). | No |

#### OpenSearch Node Groups
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `name` | string | Name of the node group. | Yes |
| `replicas` | integer | Node group replica count. | No |
| `roles` | list | Role(s) that nodes in the group will assume. May be `master`, `data`, and/or `ingest`. | Yes |
| `storage` | [Storage](#opensearch-node-group-storage) | Storage settings for the node group. | No |
| `resources` | [Resources](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/) | Kubernetes container resources for nodes in the node group. | No |

#### OpenSearch Node Group Storage
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `size` | string | Node group storage size expressed as a [Quantity](https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/quantity/#Quantity). | Yes |

#### OpenSearch Index Management Policies
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `policyName` | string | Name of the Index State Management policy. | Yes |
| `indexPattern` | string | An Index Pattern is an index name or pattern like `my-index-*`. If an index matches the pattern, the associated policy will attach to the index. | Yes |
| `minIndexAge` | [Time]({{<opensearch_docs_url>}}/opensearch/units/) | Amount of time until a managed index is deleted. Default is seven days (`7d`). | No |
| `rollover` | [Rollover](#opensearch-index-management-rollover) | Index rollover settings. | No |

#### OpenSearch Index Management Rollover
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `minIndexAge` | [Time]({{<opensearch_docs_url>}}/opensearch/units/) | Amount of time until a managed index is rolled over. Default is 1 day (`1d`). | No |
| `minSize` | [Bytes]({{<opensearch_docs_url>}}/opensearch/units/) | The size at which a managed index is rolled over. | No |
| `minDocCount` | uint32 | Amount of documents in a managed index that triggers a rollover. | No |

### OpenSearch Dashboards Component
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `enabled` | Boolean | If true, then OpenSearch Dashboards will be installed. | No |

### Prometheus Component
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `enabled` | Boolean | If true, then Prometheus will be installed. Defaults to `true`. This is a legacy setting; the preferred way to configure Prometheus is using the [prometheusOperator](#prometheus-operator-component) component. | No |

### Grafana Component
| Field | Type                                   | Description                                                                | Required |
| --- |----------------------------------------|----------------------------------------------------------------------------| --- |
| `enabled` | Boolean                                | If true, then Grafana will be installed.                                   | No |
| `replicas` | integer                                | The number of pods to replicate.  The default is `1`.                      | No |
| `database` | [DatabaseInfo](#grafana-database-info) | The information to configure a connection to an external Grafana database. | No |

### Grafana Database Info

| Field | Type   | Description                      | Required |
| --- |--------|----------------------------------| --- |
| `host` | string | The host of the database. | No |
| `name` | string | The name of the database. | No |

### Kiali Component
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `enabled` | Boolean | If true, then Kiali will be installed. | No |
| `monitorChanges` | Boolean | If false, then Verrazzano updates will ignore any configuration changes to this component. Defaults to `true`. | No |
| `overrides` | [Overrides](#overrides) list | List of Overrides for the default `values.yaml` file for the component Helm chart. Lower Overrides have precedence over the ones above them. You can find all possible values [here]( {{< release_source_url path=platform-operator/thirdparty/charts/kiali-server/values.yaml >}} ) and invalid values will be ignored. | No |

### Prometheus Operator Component
| Field     | Type    | Description                                              | Required |
|-----------|---------|----------------------------------------------------------|----------|
| `enabled` | Boolean | If true, then the Prometheus Operator will be installed. | No       |
| `monitorChanges` | Boolean | If false, then Verrazzano updates will ignore any configuration changes to this component. Defaults to `true`. | No |
| `overrides` | [Overrides](#overrides) list | List of Overrides for the default `values.yaml` file for the component Helm chart. Lower Overrides have precedence over the ones above them. You can find all possible values [here]( {{< release_source_url path=platform-operator/thirdparty/charts/prometheus-community/kube-prometheus-stack/values.yaml >}} ) and invalid values will be ignored. | No |

### Prometheus Adapter Component
| Field     | Type    | Description                                              | Required |
|-----------|---------|----------------------------------------------------------|----------|
| `enabled` | Boolean | If true, then the Prometheus Adapter will be installed.  | No       |
| `monitorChanges` | Boolean | If false, then Verrazzano updates will ignore any configuration changes to this component. Defaults to `true`. | No |
| `overrides` | [Overrides](#overrides) list | List of Overrides for the default `values.yaml` file for the component Helm chart. Lower Overrides have precedence over the ones above them. You can find all possible values [here]( {{< release_source_url path=platform-operator/thirdparty/charts/prometheus-community/prometheus-adapter/values.yaml >}} ) and invalid values will be ignored. | No |

### Kube State Metrics Component
| Field     | Type    | Description                                         | Required |
|-----------|---------|-----------------------------------------------------|----------|
| `enabled` | Boolean | If true, then kube-state-metrics will be installed. | No       |
| `monitorChanges` | Boolean | If false, then Verrazzano updates will ignore any configuration changes to this component. Defaults to `true`. | No |
| `overrides` | [Overrides](#overrides) list | List of Overrides for the default `values.yaml` file for the component Helm chart. Lower Overrides have precedence over the ones above them. You can find all possible values [here]( {{< release_source_url path=platform-operator/thirdparty/charts/prometheus-community/kube-state-metrics/values.yaml >}} ) and invalid values will be ignored. | No |

### Overrides
| Field | Type | Description | Required |
| --- | --- | --- | --- |
| `configMapRef` | [ConfigMapKeySelector](https://pkg.go.dev/k8s.io/api/core/v1@v0.23.5#ConfigMapKeySelector) | Selector for ConfigMap containing override data. | No |
| `secretRef` | [SecretKeySelector](https://pkg.go.dev/k8s.io/api/core/v1@v0.23.5#SecretKeySelector) | Selector for Secret containing override data. | No |
| `values` | [JSON](https://pkg.go.dev/k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1@v0.23.5#JSON) | Configure overrides using inline YAML. | No |

### Velero Component
| Field | Type | Description                             | Required |
| --- | --- |-----------------------------------------| --- |
| `enabled` | Boolean | If true, then Velero will be installed. | No |

### Rancher Backup Component
| Field | Type | Description                                                                                                  | Required |
| --- | --- |--------------------------------------------------------------------------------------------------------------| --- |
| `enabled` | Boolean | If true, then rancherBackup will be installed. rancherBackup is dependant on Rancher being installed. | No |