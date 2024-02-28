---
title: "OpenSearch"
weight: 1
draft: false
---
This document shows you how to install OpenSearch on OCNE.

## Verrazzano Background
Verrazzano installs OpenSearch and OpenSearch Dashboards as part of its logging stack. Prior to Verrazzano 1.7, OpenSearch and OpenSearch Dashboards were installed by the Verrazzano Monitoring Operator. Starting from version 1.7, OpenSearch and OpenSearch Dashboards are installed via the OpenSearch Operator, which can be found at [OpenSearch Operator](https://github.com/opensearch-project/opensearch-k8s-operator).

The OpenSearch Operator is installed in the cluster within the verrazzano-logging namespace and creates the **opensearch-operator-controller-manager** Deployment in the same namespace. By utilizing the OpenSearchCluster Custom Resource (CR), the operator establishes the specified OpenSearch node topology as a StatefulSet and deploys the OpenSearch Dashboards as a Deployment. For more details regarding the OpenSearch Cluster CR, refer to: [OpenSearch Cluster CR YAML](https://github.com/opensearch-project/opensearch-k8s-operator/blob/main/charts/opensearch-cluster/templates/opensearch-cluster-cr.yaml).

## OpenSearch and OpenSearch Dashboards on OCNE 2.0
Customers are advised to use the OpenSearch Operator to install OpenSearch and OpenSearch Dashboards on OCNE 2.0.

### Helm Install
OpenSearch Operator can be installed from the Community Helm Chart repository. The first step would be to add the OpenSearch Operator community Helm chart repository to the cluster.
{{< clipboard >}}
<div class="highlight">

```
$ helm repo add opensearch-operator https://opensearch-project.github.io/opensearch-k8s-operator/
$ helm repo update
```
</div>
{{< /clipboard >}}

Next, install the Helm charts.

#### Install or upgrade the OpenSearch Operator Helm chart

In the following example, `helm` command installs OpenSearch Operator in the `logging` namespace. OpenSearch Operator can be installed in any namespace as long as the same namespace is used consistently. This example assumes you are using Helm version 3.2.0 or later.

{{< clipboard >}}
<div class="highlight">

```
$ helm upgrade --install opensearch-operator opensearch-operator/opensearch-operator -n logging --create-namespace --version 2.4.0
```
</div>
{{< /clipboard >}}

Optionally, provide overrides when installing. The recipes below give examples of changing the configuration using Helm overrides.

#### Helm override recipes

##### Installing from a private registry
In order to install using a private registry (for example, in a disconnected environment), you must override Helm values to change the image registry settings for all images.

**os_operator_privreg_overrides.yaml**
{{< clipboard >}}
<div class="highlight">

```
manager:
  image:
    repository: "my.registry.io/<image>"
    tag: "<image-tag>"
kubeRbacProxy:
  image:
    repository: "my.registry.io/fluent-bit"
    tag: "<image-tag>"
```
</div>
{{< /clipboard >}}

{{< alert title="NOTE" color="primary" >}}
If you are not using kubeRbacProxy, there is no need to specify an image for kubeRbacProxy.
{{</ alert >}}

##### Pod security context
Override pod and container security default settings to limit actions that pods and containers can perform in the cluster. These settings allow pods and containers to only perform operations that are needed for them to operate successfully, and mitigate security vulnerabilities, such as privilege escalation.

**os_operator_seccontext.yaml**
{{< clipboard >}}
<div class="highlight">

```
securityContext:
  runAsNonRoot: true
  seccompProfile:
    type: RuntimeDefault
manager:
  securityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop:
        - ALL
    privileged: false
    runAsGroup: 65532
    runAsNonRoot: true
    runAsUser: 65532
```
</div>
{{< /clipboard >}}

Optionally, when installing the OpenSearch Helm chart, you can disable the kubeRbacProxy if not required using the overrides below.

{{< clipboard >}}
<div class="highlight">

```
kubeRbacProxy:
  enable: false
```
</div>
{{< /clipboard >}}


Once OpenSearch Operator is installed, you will see a **opensearch-operator-controller-manager** deployment in the **logging** namespace. If OpenSearch Operator pod is ready, you can proceed to next step.

#### Configure Admin Credentials
Create `admin-credentials-secret` secret to provide the admin credentials in the `logging` namespace. You can use existing password if it exists in older Verrazzano instance or provide a new password. You can use the below `admin-credentials-secret` by updating the password parameter(base64 encoded).
{{< clipboard >}}
<div class="highlight">

```
apiVersion: v1
kind: Secret
metadata:
  name: admin-credentials-secret
  namespace: logging
type: Opaque
data:
  password: {{ <password> | b64enc }}
  username: {{ "admin" | b64enc }
```

</div>
{{< /clipboard >}}

#### Configure Security Plugin
Create a security-config secret to configure the security plugin in the **logging** namespace of the OpenSearch operator. You can use the following secret YAML file to create the security-config secret with the name **securityconfig-secret**. 

In the below **securityconfig-secret**, you need to pass the hash of the password that you provided in the admin-credentials-secret created in the previous step.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: v1
kind: Secret
metadata:
  name: securityconfig-secret
  namespace: logging
type: Opaque
stringData:
  action_groups.yml: |-
    _meta:
      type: "actiongroups"
      config_version: 2
  internal_users.yml: |-
    _meta:
      type: "internalusers"
      config_version: 2
    admin:
      hash:  <hashed password mentioned in the admin-credentials-secret>
      reserved: true
      backend_roles:
      - "admin"
      description: "Admin user"
  nodes_dn.yml: |-
    _meta:
      type: "nodesdn"
      config_version: 2
  whitelist.yml: |-
    _meta:
      type: "whitelist"
      config_version: 2
  tenants.yml: |-
    _meta:
      type: "tenants"
      config_version: 2
  roles_mapping.yml: |-
    _meta:
      type: "rolesmapping"
      config_version: 2
    all_access:
      reserved: false
      backend_roles:
      - "admin"
      description: "Maps admin to all_access"
    own_index:
      reserved: false
      users:
      - "*"
      description: "Allow full access to an index named like the username"
    readall:
      reserved: false
      backend_roles:
      - "readall"
    manage_snapshots:
      reserved: false
      backend_roles:
      - "snapshotrestore"
    dashboard_server:
      reserved: true
      users:
      - "dashboarduser"
  roles.yml: |-
    _meta:
      type: "roles"
      config_version: 2
  config.yml: |-
    _meta:
      type: "config"
      config_version: "2"
    config:
      dynamic:
        kibana:
          multitenancy_enabled: false
        http:
          anonymous_auth_enabled: false
        authc:
          basic_internal_auth_domain:
            description: "Authenticate via HTTP Basic against internal users database"
            http_enabled: true
            transport_enabled: true
            order: 0
            http_authenticator:
              type: basic
              challenge: false
            authentication_backend:
              type: intern
          clientcert_auth_domain:
             description: "Authenticate via SSL client certificates"
             http_enabled: true
             transport_enabled: true
             order: 1
             http_authenticator:
               type: clientcert
               config:
                 enforce_hostname_verification: false
                 username_attribute: cn
               challenge: false
             authentication_backend:
                 type: noop

```

</div>
{{< /clipboard >}}

{{< alert title="NOTE" color="primary" >}}
You can create the hash of the password using below command
{{< clipboard >}}
<div class="highlight">

```
python3 -c 'import bcrypt; print(bcrypt.hashpw("your password".encode("utf-8"), bcrypt.gensalt(12, prefix=b"2a")).decode("utf-8"))'
```
</div>  
{{< /clipboard >}}
{{< /alert >}}

#### Create OpenSearch Cluster
To create OpenSearch and OpenSearch Dashboards instance, you will require to create the OpenSearchCluster CR. 

There are two ways to provide certificates in OpenSearchCluster CR.

1. One is where you can allow the OpenSearch Operator to generate and sign the certificates. You can refer below CR that has self generated certificates.

{{< alert title="NOTE" color="primary" >}}
Within this CR, specific parameter values are necessary to configure the OpenSearch Cluster according to the requirements or values outlined in the previous Verrazzano instance. You can refer to the [table]({{< relref "/docs/guides/migrate/install/opensearch#mapping-table-for-opensearchcluster-configuration" >}}) to determine the required values for these parameters.
{{</ alert >}}

{{< clipboard >}}
<div class="highlight">

```
apiVersion: opensearch.opster.io/v1
kind: OpenSearchCluster
metadata:
  name: opensearch
  namespace: logging
spec:
  {{- if .bootstrapConfig }}
  bootstrap:
    additionalConfig:
      {{ .bootstrapConfig }}
  {{- end }}
  confMgmt:
    smartScaler: true
  dashboards:
    additionalConfig:
      server.name: opensearch-dashboards
    enable: {{ .isOpenSearchDashboardsEnabled }}
    {{- if .osdPluginsEnabled }}
    pluginsList:
{{ multiLineIndent 6 .osdPluginsList }}
    {{- end }}
    opensearchCredentialsSecret:
      name: admin-credentials-secret
    replicas: {{ .osdReplicas }}
    version: 2.3.0
    podSecurityContext:
      fsGroup: 1000
      runAsGroup: 1000
      runAsNonRoot: true
      runAsUser: 1000
      seccompProfile:
        type: RuntimeDefault
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
  general:
    drainDataNodes: {{ .drainDataNodes }}
    httpPort: 9200
    serviceName: opensearch
    serviceAccount: opensearch-operator-controller-manager
    setVMMaxMapCount: true
    vendor: opensearch
    version: 2.3.0
    podSecurityContext:
      seccompProfile:
        type: RuntimeDefault
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
      privileged: false
      runAsUser: 1000
    {{- if .osPluginsEnabled }}
    pluginsList:
{{ multiLineIndent 6 .osPluginsList }}
    {{- end }}
  nodePools:
{{ multiLineIndent 4 .nodePools }}
  security:
    config:
      securityConfigSecret:
##Pre create this secret with required security configs, to override the default settings
       name: securityconfig-secret
      adminCredentialsSecret:
        name: admin-credentials-secret
    tls:
      transport:
        generate: true
      http:
        generate: true
```

</div>
{{< /clipboard >}}

2. In other way, you can create your own certificates and provide the certificate in OpenSearchCluster CR. Refer next section<TBD> to know how to generate certificates.

{{< clipboard >}}
<div class="highlight">

```
apiVersion: opensearch.opster.io/v1
kind: OpenSearchCluster
metadata:
  name: opensearch
  namespace: logging
spec:
  {{- if .bootstrapConfig }}
  bootstrap:
    additionalConfig:
      {{ .bootstrapConfig }}
  {{- end }}
  confMgmt:
    smartScaler: true
  dashboards:
    additionalConfig:
      server.name: opensearch-dashboards
    enable: {{ .isOpenSearchDashboardsEnabled }}
    {{- if .osdPluginsEnabled }}
    pluginsList:
{{ multiLineIndent 6 .osdPluginsList }}
    {{- end }}
    opensearchCredentialsSecret:
      name: admin-credentials-secret
    replicas: {{ .osdReplicas }}
    tls:
      enable: true
      generate: false
      secret:
        name: opensearch-dashboards-cert
    version: 2.3.0
    podSecurityContext:
      fsGroup: 1000
      runAsGroup: 1000
      runAsNonRoot: true
      runAsUser: 1000
      seccompProfile:
        type: RuntimeDefault
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
  general:
    drainDataNodes: {{ .drainDataNodes }}
    httpPort: 9200
    serviceName: opensearch
    serviceAccount: opensearch-operator-controller-manager
    setVMMaxMapCount: true
    vendor: opensearch
    version: 2.3.0
    podSecurityContext:
      seccompProfile:
        type: RuntimeDefault
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
      privileged: false
      runAsUser: 1000
    {{- if .osPluginsEnabled }}
    pluginsList:
{{ multiLineIndent 6 .osPluginsList }}
    {{- end }}
  nodePools:
{{ multiLineIndent 4 .nodePools }}
  security:
    config:
      adminCredentialsSecret:
        name: admin-credentials-secret
      securityConfigSecret:
        name: securityconfig-secret
      adminSecret:
        name: opensearch-admin-cert
    tls:
      transport:
        generate: false
        secret:
          name: opensearch-node-cert
        adminDn: [ "CN=admin,O=<org name>" ]
        nodesDn: [ "CN=opensearch,O=<org name>" ]
      http:
        generate: false
        secret:
          name: opensearch-master-cert
```
</div>
{{< /clipboard >}}

##### mapping table for OpenSearchCluster configuration
You can utilise the table given below to get the correct configuration for your cluster.

| Parameter                     | Description                                                                                | Verrazzano Default value (Dev profile)                                                                                                                                                            | Verrazzano Default Value (Prod profile)                                                                                                                                                                                                                                                                                                                  | Mapped Verrazzano CR Key                                                                                                                                                                                                            |
|-------------------------------|--------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| osdReplicas                   | number of OpenSearch Dashboards replicas                                                   | 1                                                                                                                                                                                                 | 1                                                                                                                                                                                                                                                                                                                                                        | spec.components.opensearchDashboards.replicas                                                                                                                                                                                       |
| osdPluginsList                | list of plugins to be dynamically installed in OpenSearch Dashboards                       | [ ]                                                                                                                                                                                               | [ ]                                                                                                                                                                                                                                                                                                                                                      | spec.components.opensearchDashboards.plugins.installList                                                                                                                                                                            |
| osdPluginsEnabled             | Whether any external plugins needs to be dynamically installed or not in OSD               | false                                                                                                                                                                                             | false                                                                                                                                                                                                                                                                                                                                                    | spec.components.opensearchDashboards.plugins.enabled                                                                                                                                                                                |
| osPluginsList                 | list of plugins to be dynamically installed in OpenSearch                                  | [ ]                                                                                                                                                                                               | [ ]                                                                                                                                                                                                                                                                                                                                                      | spec.components.opensearch.plugins.installList                                                                                                                                                                                      |
| osPluginsEnabled              | Whether any external plugins needs to be dynamically installed or not in OpenSearch        | false                                                                                                                                                                                             | false                                                                                                                                                                                                                                                                                                                                                    | spec.components.opensearch.plugins.enabled                                                                                                                                                                                          |
| nodePools[*].diskSize         | Node group storage size                                                                    | 1Gi                                                                                                                                                                                               | es-master -> 50Gi es-data -> 50Gi es-ingest -> 1Gi                                                                                                                                                                                                                                                                                                       | spec.components.opensearch.nodes[*].storage if above value is not defined , then get it from storage spec storageSpec.resources.requests.storage defined in the Volume template for spec.defaultVolumeSource.persistentVolumeClaim. |
| nodePools[*].roles            | list of roles that nodes in the group will assume                                          | [ master, data]                                                                                                                                                                                   | es-master -> [master] es-data -> [data] es-ingest -> [ingest]                                                                                                                                                                                                                                                                                            | spec.components.opensearch.nodes[*].roles                                                                                                                                                                                           |
| nodePools[*].resources        | configures the compute resource requirements.                                              | resources:  requests:  memory: 1G                                                                                                                                                                 | For es-master: resources:  requests:  memory: 1.4Gi <br/>For es-data resources:  requests:  memory: 4.8Gi <br/>For es-ingest resources:  requests:  memory: 2.5Gi                                                                                                                                                                                        | spec.components.opensearch.nodes[*].resources                                                                                                                                                                                       |
| nodePools[*].replicas         | number of openSearch nodes                                                                 | 1                                                                                                                                                                                                 | es-master -> 3 es-data -> 3 es-ingest -> 1                                                                                                                                                                                                                                                                                                               | spec.components.opensearch.nodes[*].replicas                                                                                                                                                                                        |
| nodePools[*].component        | name of the node.                                                                          | es-master                                                                                                                                                                                         | es-master, es-ingest, es-data                                                                                                                                                                                                                                                                                                                            | spec.components.opensearch.nodes[*].name                                                                                                                                                                                            |
| nodePools[*].jvm              | JVM configuration of the node.                                                             | {}                                                                                                                                                                                                | {}                                                                                                                                                                                                                                                                                                                                                       | spec.components.opensearch.nodes[*].javaOpts                                                                                                                                                                                        |
| nodePools                     | list of OpenSearch node groups.                                                            | nodePools:- additionalConfig: cluster.initial_master_nodes: opensearch-es-master-0  component: es-master  diskSize: 1Gi  replicas: 1  resources:  requests:  memory: 1G  roles:  - master  - data | nodePools: <br/>- component: es-master  diskSize: 50Gi  replicas: 3  resources:  requests:  memory: 4.8Gi  roles:  - master <br/>- component: es-data  diskSize: 50Gi  replicas: 3  resources:  requests:  memory: 1.4Gi  roles:  - data <br/>- component: es-ingest  diskSize: 1Gi  replicas: 1  resources:  requests:  memory: 2.5Gi  roles:  - ingest | spec.components.opensearch.nodes                                                                                                                                                                                                    |
| isOpenSearchDashboardsEnabled | whether to enable OpenSearch Dashboards or not.                                            | true                                                                                                                                                                                              | true                                                                                                                                                                                                                                                                                                                                                     | spec.components.kibana.enabled or spec.components.opensearchDashboards.enabled                                                                                                                                                      |
| bootstrapConfig               | items to add to the opensearch.yml                                                         | "cluster.initial_master_nodes:opensearch-es-master-0"                                                                                                                                             | ""                                                                                                                                                                                                                                                                                                                                                       | based on spec.profile                                                                                                                                                                                                               |
| drainDataNodes                | whether data nodes need to be drained. only works on nodes that singed as DATA roles nodes | false                                                                                                                                                                                             | true                                                                                                                                                                                                                                                                                                                                                     | based on spec.profile                                                                                                                                                                                                               |
| nodePools[*].additionalConfig | additional configuration for the node group                                                | cluster.initial_master_nodes: opensearch-es-master-0                                                                                                                                              | ""                                                                                                                                                                                                                                                                                                                                                       | based on spec.profile                                                                                                                                                                                                               |


##### OpenSearchCluster CR with Default values
**Prod Profile**
{{< clipboard >}}
<div class="highlight">

```
apiVersion: opensearch.opster.io/v1
kind: OpenSearchCluster
metadata:
  finalizers:
  - Opster
  name: opensearch
  namespace: logging
spec:
  bootstrap:
    resources: {}
  confMgmt:
    smartScaler: true
  dashboards:
    additionalConfig:
      server.name: opensearch-dashboards
    enable: true
    opensearchCredentialsSecret:
      name: admin-credentials-secret
    podSecurityContext:
      fsGroup: 1000
      runAsGroup: 1000
      runAsNonRoot: true
      runAsUser: 1000
      seccompProfile:
        type: RuntimeDefault
    replicas: 1
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
    version: 2.3.0
  general:
    drainDataNodes: true
    httpPort: 9200
    podSecurityContext:
      seccompProfile:
        type: RuntimeDefault
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      privileged: false
      runAsUser: 1000
    serviceAccount: opensearch-operator-controller-manager
    serviceName: opensearch
    setVMMaxMapCount: true
    vendor: opensearch
    version: 2.3.0
  nodePools:
  - component: es-master
    diskSize: 50Gi
    replicas: 3
    resources:
      requests:
        memory: 1503238553600m
    roles:
    - master
  - component: es-data
    diskSize: 50Gi
    replicas: 3
    resources:
      requests:
        memory: 5153960755200m
    roles:
    - data
  - component: es-ingest
    diskSize: 1Gi
    replicas: 1
    resources:
      requests:
        memory: 2560Mi
    roles:
    - ingest
  security:
    config:
      securityConfigSecret:
      #Pre create this secret with required security configs, to override the default settings
       name: securityconfig-secret
      adminCredentialsSecret:
        name: admin-credentials-secret
    tls:
      transport:
        generate: true
      http:
        generate: true
```
</div>
{{< /clipboard >}}

**Dev Profile**
{{< clipboard >}}
<div class="highlight">

```
apiVersion: opensearch.opster.io/v1
kind: OpenSearchCluster
metadata:
  finalizers:
  - Opster
  name: opensearch
  namespace: <opensearch dedicated namespace>
spec:
  bootstrap:
    additionalConfig:
      cluster.initial_master_nodes: opensearch-es-master-0
  confMgmt:
    smartScaler: true
  dashboards:
    additionalConfig:
      server.name: opensearch-dashboards
    enable: true
    opensearchCredentialsSecret:
      name: admin-credentials-secret
    podSecurityContext:
      fsGroup: 1000
      runAsGroup: 1000
      runAsNonRoot: true
      runAsUser: 1000
      seccompProfile:
        type: RuntimeDefault
    replicas: 1
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
    version: 2.3.0
  general:
    drainDataNodes: false
    httpPort: 9200
    podSecurityContext:
      seccompProfile:
        type: RuntimeDefault
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      privileged: false
      runAsUser: 1000
    serviceAccount: opensearch-operator-controller-manager
    serviceName: opensearch
    setVMMaxMapCount: true
    vendor: opensearch
    version: 2.3.0
  nodePools:
  - additionalConfig:
      cluster.initial_master_nodes: opensearch-es-master-0
    component: es-master
    diskSize: 1Gi
    replicas: 1
    resources:
      requests:
        memory: 1G
    roles:
    - master
    - data
security:
    config:
      securityConfigSecret:
##Pre create this secret with required security configs, to override the default settings
       name: securityconfig-secret
      adminCredentialsSecret:
        name: admin-credentials-secret
    tls:
      transport:
        generate: true
      http:
        generate: true
```
</div>
{{< /clipboard >}}

Once OpenSearchCluster CR is created, you will see OpenSearch and OpenSearch Dashboards pods coming up.

#### Create ISM Policies
(Optional) Create  ISM policies to manage your indices. In the OpenSearch Dashboards, navigate to the Dev Tools console to send queries to OpenSearch. Execute the following queries to create ISM policies.
Below are the default ISM policies that we create in Verrazzano.
{{< alert title="NOTE" color="primary" >}}
You need to modify these according to the requirements or resources on your cluster. Consider changing name of the policy and the index patterns mentioned in the policies below based on the requirements and your setup.
{{</ alert >}}

{{< clipboard >}}
<div class="highlight">

```

PUT _plugins/_ism/policies/vz-system
{
  "policy":{
    "description":"Verrazzano system default ISM Policy",
    "default_state":"hot",
    "schema_version":1,
    "states":[
      {
        "name":"hot",
        "actions":[
          {
            "retry":{
              "count":3,
              "backoff":"exponential",
              "delay":"10m"
            },
            "rollover":{
              "min_primary_shard_size":"5gb",
              "min_index_age":"21d"
            }
          }
        ],
        "transitions":[
          {
            "state_name":"delete",
            "conditions":{
              "min_rollover_age":"14d"
            }
          }
        ]
      },
      {
        "name":"delete",
        "actions":[
          {
            "retry":{
              "count":3,
              "backoff":"exponential",
              "delay":"10m"
            },
            "delete":{
 
            }
          }
        ]
      }
    ],
    "ism_template":[
      {
        "index_patterns":[
          "verrazzano-system" # change it to the index pattern that covers component logs.
        ],
        "priority":0
      }
    ]
  }
}
```
</div>
{{< /clipboard >}}

{{< clipboard >}}
<div class="highlight">

```
PUT _plugins/_ism/policies/vz-application
{
  "policy":{
    "description":"Verrazzano application default ISM Policy",
    "default_state":"hot",
    "schema_version":1,
    "states":[
      {
        "name":"hot",
        "actions":[
          {
            "retry":{
              "count":3,
              "backoff":"exponential",
              "delay":"10m"
            },
            "rollover":{
              "min_primary_shard_size":"5gb",
              "min_index_age":"21d"
            }
          }
        ],
        "transitions":[
          {
            "state_name":"delete",
            "conditions":{
              "min_rollover_age":"14d"
            }
          }
        ]
      },
      {
        "name":"delete",
        "actions":[
          {
            "retry":{
              "count":3,
              "backoff":"exponential",
              "delay":"10m"
            },
            "delete":{
 
            }
          }
        ]
      }
    ],
    "ism_template":[
      {
        "index_patterns":[
          "verrazzano-application*" # change it to the index pattern that covers application logs.
        ],
        "priority":0
      }
    ]
  }
}
```
</div>
{{< /clipboard >}}

#### Create Index Patterns
Index patterns are essential for accessing OpenSearch data. To access specific logs, create index patterns based on your data-stream and index patterns.

Below are the index pattern that we create in Verrazzano to access the Verrazzano specific logs.

1. **verrazzano-system**: to cover Verrazano component logs.
2. **verrazzano-application**: to cover Application logs.

{{< alert title="NOTE" color="primary" >}}
You need to create your own index patterns based on the indices you intend to access.
{{</ alert >}}
To create the index pattern, go to OpenSearch Dashboards, and select Management > Dashboards Management > Index patterns. 

Select Create index pattern.

From the Create index pattern window, define the index pattern by entering a name for your index pattern in the Index pattern name field.

Select Next step. 

Select **@timestamp** from the dropdown menu to specify the time field for OpenSearch to use when filtering documents based on time. 

Select Create index pattern.

#### OpenSearch Data Migration:

There is existing documentation for Verrazzano that provides guidance on backing up and restoring OpenSearch data. You can follow the instructions outlined in [Verrazzano documentation]({{< relref "/docs/backup/opensearch.md#opensearch-backup-using-velero" >}}) for using Velero to back up and restore data.

Alternatively, instead of restoring the data using Velero, you can refer to the documentation on [restoring data using the OpenSearch API]({{< relref "/docs/backup/opensearch.md#opensearch-restore-in-an-existing-cluster-using-opensearch-api" >}}).

Additionally, OpenSearch's official documentation provides resources on taking snapshots using the OpenSearch API and restoring data. You can find more information [here](https://opensearch.org/docs/latest/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-restore/#shared-file-system).