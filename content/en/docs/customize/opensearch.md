---
title: "OpenSearch"
description: "Learn how to customize your OpenSearch cluster configuration"
aliases:
- /docs/customize/elasticsearch
linkTitle: OpenSearch
weight: 10
draft: false
---

Verrazzano supports two cluster topologies for an OpenSearch cluster:
- A single-node cluster: master, ingest, and data roles performed by a single node.
- A multi-node cluster configuration with separate master, data, and ingest nodes.

For information about the default OpenSearch cluster configurations provided by Verrazzano, see [Installation Profiles]({{< relref "/docs/setup/install/profiles.md" >}}).
## Plan cluster topology

Start with an initial estimate of your hardware needs. The following recommendations will provide you with initial, educated estimates, but for ideal sizing, you will need to test them with representative workloads, monitor their performance, and then reiterate.

#### Storage Requirements

| Input    | Description                                                   | Value    |
|:----|---------------------------------------------------------------|:----|
| \\(s\\)    | Stored data size in GiB (log size per day * days to retain). | User defined    |
| \\(sr\\)    | Shard replica count per index.                                | User defined    |
| \\(o\\)     | Overall overhead, which is a constant.                          | 1.45    |


  Minimum storage requirement = \\( ( s * ( 1 + sr ) ) * o \\)

  #### Example

  If you have  \\(s\\) = 66 GiB (6 GiB of log size per day * 11 days to retain) and, if you choose one shard replica per index, which makes \\(sr\\) = 1

  Then, minimum storage requirement = \\((66 * (1 + 1) ) * 1.45\\) = 192 GiB

  _Overhead_, which is defined in the previous table, can be further explained as follows.

  | Input    | Description                                                                                                                 | Value         |
|-----|-----------------------------------------------------------------------------------------------------------------------------|---------------|
| \\(io\\)    | Indexing overhead: Extra space used other than the actual data, which is generally 10% ( 0.1 ) of the index size.         | 1 + 0.1 = 1.1 |
|   \\(lrs\\)          | Linux reserved space: Linux reserves 5% of the file system for the root user for some OS operations.                       | 1- 0.05 = .95 |
|    \\(oo\\)         | OpenSearch overhead: OpenSearch keeps a maximum 20% of the instance for segment merges, logs, and other internal operations. | 1- 0.2 = 0.8  |


   Overall overhead \\(o\\) = \\( io / lrs / oo \\) = 1.45

#### Memory

  For every 100 GiB of your storage requirement, you should have 8 GiB of memory.

  With reference to the [Example](#example):

  For 192 GiB of storage requirement, you need 16 GiB of memory.

#### Number of Data Nodes

|  Input   | Description                                                                                                                            | Value        |
|-----|----------------------------------------------------------------------------------------------------------------------------------------|--------------|
|  \\(ts\\)   | Total storage in GiB.                                                                                                                   | User defined |
| \\(mem\\)   | Memory per data node in GiB.                                                                                                            | User defined |
|  \\(md\\)   | Memory:data ratio (1:30 ratio means that you have 30 times more storage on the node than you have RAM; the value used would be 30). | User defined |
|  \\(fc\\)   | One data node for failover capacity, which is a constant.                                                                               | 1            |

  ROUNDUP \\(ts / mem / md  + fc\\)

  With reference to the [Example](#example):

  \\(ts\\) = 192 GiB , \\(mem\\) = 8 GiB , \\(md\\) = 1:10 and \\(fc\\) = 1

  Then, number of data nodes = ROUNDUP \\( 192 / 8 / 10  + 1 \\) = 3

#### JVM heap memory

  The heap size is the amount of RAM allocated to the JVM of an OpenSearch node. The OpenSearch process is very memory intensive and close to 50% of the memory available on a node should be allocated to the JVM. The JVM machine uses memory for indexing and search operations. The other 50% is required for the file system cache, which keeps data that is regularly accessed in memory.
  As a general rule, you should set `-Xms` and `-Xmx` to the same value, which should be 50% of your total available RAM, subject to a maximum of (approximately) 31 GiB.

#### CPU

  Hardware requirements vary dramatically by workload, but, typically, two vCPU cores for every 100 GiB of your storage requirement is sufficient.

  With reference to the [Example](#example):

  For 192 GiB of storage, the vCPU cores required are 4.


#### Shard Size

  For logging, shard sizes between 10 GiB and 50 GiB typically perform well.
  For search-intensive operations, 10-25 GiB typically is a good shard size. Overall, it is a best practice that, for a single shard, the OpenSearch shard size should not go above 50GiB. When the shards exceed 50 GiB, you will have to reindex your data.


#### Primary shards count


| Input    | Description                                                                                                | Value        |
|----------|------------------------------------------------------------------------------------------------------------|--------------|
| \\(s\\)  | Stored data size in GiB (log size per day * days to retain).                                              | User defined |
| \\(sh\\) | Desired shard size in GiB.                                                                                  | User defined |
| \\(io\\) | Indexing overhead: Extra space used other than the actual data which is generally 10% of the index size. | 0.1          |


   Primary shards = \\( ( s * (1 + io) ) / sh \\)

   With reference to the [Example](#example):

   \\(s\\) = 66 GiB and if you choose shard size \\(sh\\) = 30 GiB

   Then, primary shards count = \\( ( 66 * 1.1 )/ 30 \\) = 2



## Recommended alarms
You can [customize Prometheus]({{< relref "/docs/observability/monitoring/metrics/configure/prometheus/prometheus.md" >}}) to enable Alertmanager and configure recommended alarms (add alert rules) to get insight into your OpenSearch cluster and take some actions proactively.

Use the `OSDataNodeFilesystemSpaceFillingUp` alert to indicate that the OpenSearch average disk usage has exceeded the specified threshold. Adjust the alert thresholds according to your needs.
   ```yaml
   kubectl apply -f - <<EOF
   apiVersion: monitoring.coreos.com/v1
   kind: PrometheusRule
   metadata:
     labels:
       release: prometheus-operator
     name: prometheus-operator-os
     namespace: verrazzano-monitoring
   spec:
     groups:
       - name: os
         rules:
           - alert: OSDataNodeFilesystemSpaceFillingUp
             annotations:
               runbook_url: <link to runbook>
               summary: Opensearch average disk usage exceeded 75%.
             expr: |-
               1 - (es_fs_total_available_bytes{node=~".*data.*"}/ es_fs_total_total_bytes) > .75
             for: 30m
             labels:
               severity: warning
     EOF
  ```


## Configure cluster topology

You can customize the node characteristics of your OpenSearch cluster by using the
[spec.components.opensearch.nodes](/docs/reference/api/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.OpenSearchNode)
field in the Verrazzano custom resource.  When installing or upgrading Verrazzano, you can use this field to
define an OpenSearch cluster using node groups.

The following example overrides the `dev` installation profile, OpenSearch configuration (a single-node cluster with
1Gi of memory and ephemeral storage) to use a multi-node cluster (three master nodes, and three combination data/ingest nodes) with persistent storage.

{{< clipboard >}}
```yaml
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: custom-opensearch-example
spec:
  profile: dev
  components:
    opensearch:
      nodes:
        - name: master
          replicas: 3
          roles:
            - master
          storage:
            size: 50Gi
          resources:
            requests:
              memory: 1.5Gi
        - name: data-ingest
          replicas: 3
          roles:
            - data
            - ingest
          storage:
            size: 100Gi
          resources:
            requests:
              memory: 1Gi
        # Override the default node groups because we are providing our own topology.
        - name: os-master
          replicas: 0
        - name: os-data
          replicas: 0
        - name: os-ingest
          replicas: 0
```
{{< /clipboard >}}

Listing the pods and persistent volumes in the `verrazzano-system` namespace for the previous configuration
shows the expected nodes are running with the appropriate data volumes.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get pvc,pod -l verrazzano-component=opensearch -n verrazzano-system

# Sample output
NAME                                                             STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS   AGE
persistentvolumeclaim/opensearch-master-vmi-system-master-0      Bound    pvc-9ace042a-dd68-4975-816d-f2ca0dc4d9d8   50Gi       RWO            standard       5m22s
persistentvolumeclaim/opensearch-master-vmi-system-master-1      Bound    pvc-8bf68c2c-235e-4bd5-8741-5a5cd3453934   50Gi       RWO            standard       5m21s
persistentvolumeclaim/opensearch-master-vmi-system-master-2      Bound    pvc-da8a48b1-5762-4669-98f0-8479f30043fc   50Gi       RWO            standard       5m21s
persistentvolumeclaim/vmi-system-data-ingest                     Bound    pvc-7ad9f275-632b-4aac-b7bf-c5115215937c   100Gi      RWO            standard       5m23s
persistentvolumeclaim/vmi-system-data-ingest-1                   Bound    pvc-8a293e51-2c20-4cae-916b-1ce46a780403   100Gi      RWO            standard       5m23s
persistentvolumeclaim/vmi-system-data-ingest-2                   Bound    pvc-0025fcef-1d8c-4307-977c-3921545c6730   100Gi      RWO            standard       5m22s

NAME                                                   READY   STATUS     RESTARTS   AGE
pod/coherence-operator-6ffb6bbd4d-bpssc                1/1     Running    1          8m2s
pod/fluentd-ndshl                                      2/2     Running    0          5m51s
pod/oam-kubernetes-runtime-85cfd899d8-z9gv6            1/1     Running    0          8m14s
pod/verrazzano-application-operator-5fbcdf6655-72tw9   1/1     Running    0          7m49s
pod/verrazzano-authproxy-5f9d479455-5bvvt              2/2     Running    0          7m43s
pod/verrazzano-console-5b857d7b47-djbrk                2/2     Running    0          5m51s
pod/verrazzano-monitoring-operator-b4b446567-pgnfw     2/2     Running    0          5m51s
pod/vmi-system-data-ingest-0-5485dcd95d-rkhvk          2/2     Running    0          5m21s
pod/vmi-system-data-ingest-1-8d7db6489-kdhbv           2/2     Running    1          5m21s
pod/vmi-system-data-ingest-2-699d6bdd9c-z7nzx          2/2     Running    0          5m21s
pod/vmi-system-grafana-7947cdd84b-b7mks                2/2     Running    0          5m21s
pod/vmi-system-kiali-6c7bd6658b-d2zq9                  2/2     Running    0          5m37s
pod/vmi-system-opensearchDashboards-7d47f65dfc-zhjxp   2/2     Running    0          5m21s
pod/vmi-system-master-0                                2/2     Running    0          5m21s
pod/vmi-system-master-1                                2/2     Running    0          5m21s
pod/vmi-system-master-2                                2/2     Running    0          5m21s
pod/weblogic-operator-666b548749-lj66t                 2/2     Running    0          7m48s
```

</div>
{{< /clipboard >}}

Running the command `kubectl describe pod -n verrazzano-system vmi-system-data-ingest-0-5485dcd95d-rkhvk` shows the
requested amount of memory.
{{< clipboard >}}
<div class="highlight">

```
Containers:
  os-data:
    ...
    Requests:
      memory:   1Gi
```

</div>
{{< /clipboard >}}

## Default Index State Management policies

[Index State Management]({{<opensearch_docs_url>}}/im-plugin/ism/index/) (ISM) policies configure OpenSearch to manage the data in your indices.
You can use policies to automatically rollover and prune old data, preventing your OpenSearch
cluster from running out of disk space.

To help you manage issues, such as low disk space, the following two ISM policies are created by default:
- `vz-system`: Manages the data in the Verrazzano system index.

  ![vz-system](/docs/images/vz-system-ism-policy.png)
- `vz-application`: Manages the data in the application-related indices having the pattern, `verrazzano-application*`.

  ![vz-application](/docs/images/vz-application-ism-policy.png)

Both ISM policies have three states:
- **Hot**: This is the default state. If the primary shard size is greater than the defined size (5 GB for `vz-system` and 1 GB for `vz-application`) or the index age is greater than the defined number of days (30 days for `vz-system` and 7 days for `vz-application`), then the index will be rolled over.
- **Cold**:  In this state, the index will be closed if the index age is greater than the defined number of days (30 days for `vz-system` and 7 days for `vz-application`). A closed index is blocked for read or write operations and does not allow any operations that the opened indices allow.
- **Delete**: In this state, the index will be deleted if the index age is greater than the defined number of days (35 days for `vz-system` and 12 days for `vz-application`).


## Override default ISM policies
The `vz-system` and `vz-application` policies are immutable and any change to these policies will be reverted immediately. However, the following two methods will override this behavior:
- **Disable default policies**: You can disable the use of these default policies by setting the flag [spec.components.opensearch.disableDefaultPolicy](/docs/reference/api/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.OpenSearchComponent) to `true` in the Verrazzano CR. This will delete the default ISM policies.
- **Override default policies**: Both these default policies have a zero (`0`) priority. You can override the default policies by creating policies with `policy.ism_template.priority` greater than `0`. Check [Configure ISM Policies](/docs/customize/opensearch/#configure-ism-policies) in order to configure/create your own policies.

{{< alert title="NOTE" color="primary" >}}
- Avoid creating policies with policy IDs `vz-system` or `vz-application` because they are reserved for Verrazzano default policies names. In the Verrazzano CR, by default, if the flag [spec.components.opensearch.disableDefaultPolicy](/docs/reference/api/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.OpenSearchComponent) is set to `false`, then policies that are created with these names will be overridden with the default ISM policies, .
- The default policy will be applied only to the newly created indices. To manually attach the new policies to the older indices, see [Step 2: Attach policies to indexes](https://opensearch.org/docs/latest/im-plugin/ism/index/#step-2-attach-policies-to-indexes).
  {{< /alert >}}

## Configure ISM policies

Verrazzano lets you configure OpenSearch ISM policies using the Verrazzano custom resource.
The ISM policy created by Verrazzano will contain two states: ingest and delete. The ingest state can be configured only for the rollover action.
The rollover action for the ingest state will be configured based on the rollover configuration provided in the Verrazzano custom resource.

The following policy example configures OpenSearch to manage indices matching the pattern `my-app-*`. The data in these indices will be
automatically pruned every 14 days, and will be rolled over if an index meets at least one of the following criteria:
- Is three or more days old
- Contains 1,000 documents or more
- Is 10 GB in size or larger

{{< clipboard >}}

```yaml
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: custom-opensearch-example
spec:
  profile: dev
  components:
    opensearch:
      policies:
        - policyName: my-app
          indexPattern: my-app-*
          minIndexAge: 14d
          rollover:
            minIndexAge: 3d
            minDocCount: 1000
            minSize: 10gb
```
{{< /clipboard >}}
The previous Verrazzano custom resource will generate the following ISM policy.

{{< clipboard >}}

```json
{
  "_id" : "my-app",
  "_version" : 17,
  "_seq_no" : 16,
  "_primary_term" : 1,
  "policy" : {
    "policy_id" : "my-app",
    "description" : "__vmi-managed__",
    "last_updated_time" : 1671096525963,
    "schema_version" : 12,
    "error_notification" : null,
    "default_state" : "ingest",
    "states" : [
      {
        "name" : "ingest",
        "actions" : [
          {
            "rollover" : {
              "min_size" : "10gb",
              "min_doc_count" : 1000,
              "min_index_age" : "3d"
            }
          }
        ],
        "transitions" : [
          {
            "state_name" : "delete",
            "conditions" : {
              "min_index_age" : "14d"
            }
          }
        ]
      },
      {
        "name" : "delete",
        "actions" : [
          {
            "delete" : { }
          }
        ],
        "transitions" : [ ]
      }
    ],
    "ism_template" : [
      {
        "index_patterns" : [
          "my-app-*"
        ],
        "priority" : 1,
        "last_updated_time" : 1671096525963
      }
    ]
  }
}
```

{{< /clipboard >}}

**NOTE**: The ISM policy created using the Verrazzano custom resource contains a minimal set of configurations. To create a more detailed ISM policy,
you can also use the OpenSearch REST API. To create a policy using the OpenSearch API, do the following:

{{< clipboard >}}

```bash
$ PASS=$(kubectl get secret \
    --namespace verrazzano-system verrazzano \
    -o jsonpath={.data.password} | base64 \
    --decode; echo)

$ HOST=$(kubectl get ingress \
    -n verrazzano-system vmi-system-os-ingest \
    -o jsonpath={.spec.rules[0].host})

$ curl -ik -X PUT --user verrazzano:$PASS https://$HOST/_plugins/_ism/policies/policy_3 \
    -H 'Content-Type: application/json' \
    --data-binary @- << EOF
{
  "policy": {
    "description": "ingesting logs",
    "default_state": "ingest",
    "states": [
      {
        "name": "ingest",
        "actions": [
          {
            "rollover": {
              "min_doc_count": 5
            }
          }
        ],
        "transitions": [
          {
            "state_name": "search"
          }
        ]
      },
      {
        "name": "search",
        "actions": [],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": {
              "min_index_age": "5m"
            }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [
          {
            "delete": {}
          }
        ],
        "transitions": []
      }
    ]
  }
}
EOF
```
{{< /clipboard >}}
To view existing policies, do the following:

{{< clipboard >}}

```bash
$ curl -ik \
    --user verrazzano:$PASS https://$HOST/_plugins/_ism/policies
```
{{< /clipboard >}}

## Override default number of shards and replicas

Verrazzano provides a default index template, `verrazzano-data-stream`. In initial Verrazzano v1.5 installations (not upgrades), the default index template creates one shard and one replica for each index. (In previous and upgrade installations, it creates five shards and one replica.) You can override the default number of shards or replicas by overriding the default index template.

To do that, you need to get the default index template, copy the contents and change the number of shards, replicas, and index pattern, and then create your own index template with a higher priority so that the new template will override the default one.

You can use the OpenSearch Dev Tools Console to send given queries to OpenSearch. To open the console, select Dev Tools on the main OpenSearch Dashboards page and write your queries in the editor pane on the left side of the console.

To get the existing, default template:
{{< clipboard >}}
```yaml
$ GET /_index_template/verrazzano-data-stream
```
{{< /clipboard >}}


Here is an example to create a new index template, which changes the number of shards to `3` and replicas to `2`.
{{< clipboard >}}
```yaml
$ PUT _index_template/my-template
    {
        "index_patterns" : [
          "verrazzano-application-myapp*"
        ],
        "template" : {
          "settings" : {
            "index" : {
              "mapping" : {
                "total_fields" : {
                  "limit" : "2000"
                }
              },
              "refresh_interval" : "5s",
              "number_of_shards" : "3",
              "auto_expand_replicas" : "0-1",
              "number_of_replicas" : "2"
            }
          },
          "mappings" : {
            "dynamic_templates" : [
              {
                "message_field" : {
                  "path_match" : "message",
                  "mapping" : {
                    "norms" : false,
                    "type" : "text"
                  },
                  "match_mapping_type" : "string"
                }
              },
              {
                "object_fields" : {
                  "mapping" : {
                    "type" : "object"
                  },
                  "match_mapping_type" : "object",
                  "match" : "*"
                }
              },
              {
                "all_non_object_fields" : {
                  "mapping" : {
                    "norms" : false,
                    "type" : "text",
                    "fields" : {
                      "keyword" : {
                        "ignore_above" : 256,
                        "type" : "keyword"
                      }
                    }
                  },
                  "match" : "*"
                }
              }
            ],
            "properties" : {
              "@timestamp" : {
                "format" : "strict_date_time||strict_date_optional_time||epoch_millis",
                "type" : "date"
              }
            }
          }
        },
        "priority" : 201,
        "data_stream" : {
          "timestamp_field" : {
            "name" : "@timestamp"
          }
        }
}
```
{{< /clipboard >}}
With this example, new indices that match the `verrazzano-application-myapp*` index pattern will be created with three shards and two replicas, and other indices that don't match will continue to be created with the default number of shards and replicas.
For more information, see [Index templates ](https://opensearch.org/docs/latest/opensearch/index-templates/) in the OpenSearch documentation.

## Install OpenSearch and OpenSearch Dashboards plug-ins
Verrazzano supports OpenSearch and OpenSearch Dashboard plug-in installation by providing plug-ins in the Verrazzano custom resource.
To install plug-ins for OpenSearch, you define the field [spec.components.opensearch.plugins](/docs/reference/api/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.OpenSearchComponent) in the Verrazzano custom resource.

The following Verrazzano custom resource example installs the `analysis-stempel` and `opensearch-anomaly-detection` plug-ins for OpenSearch:

{{< clipboard >}}

```yaml
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: custom-opensearch-example
spec:
  profile: dev
  components:
    opensearch:
      plugins:
        enabled: true
        installList:
          - analysis-stempel
          - https://repo1.maven.org/maven2/org/opensearch/plugin/opensearch-anomaly-detection/2.2.0.0/opensearch-anomaly-detection-2.2.0.0.zip
```
{{< /clipboard >}}

#### Pre-built plug-ins for OpenSearch
Here are some pre-built plug-ins that are bundled with the OpenSearch image:
- `analysis-icu`
- `analysis-kuromoji`
- `analysis-phonetic`
- `analysis-smartcn`
- `ingest-attachment`
- `mapper-murmur3`
- `mapper-size`
- `opensearch-index-management`
- `opensearch-job-scheduler`
- `prometheus-exporter`
- `repository-s3`

There are three ways to specify a plug-in in the `plugins.installList`:
- [Specify a plug-in by name]({{<opensearch_docs_url>}}/install-and-configure/plugins#install-a-plugin-by-name):

  There are some pre-built [additional plug-ins]({{<opensearch_docs_url>}}/install-and-configure/plugins#additional-plugins) that are the only plug-ins you can install by name.

  {{< clipboard >}}

  ```yaml
  installList:
          - analysis-icu
  ```
  {{< /clipboard >}}
- [Specify a plug-in from a remote ZIP file]({{<opensearch_docs_url>}}/install-and-configure/plugins#install-a-plugin-from-a-zip-file):

  Provide the URL to a remote ZIP file that contains the required plug-in.
  {{< clipboard >}}

  ```yaml
  installList:
          - https://repo1.maven.org/maven2/org/opensearch/plugin/opensearch-anomaly-detection/2.2.0.0/opensearch-anomaly-detection-2.2.0.0.zip
  ```
  {{< /clipboard >}}
- [Specify a plug-in using Maven coordinates]({{<opensearch_docs_url>}}/install-and-configure/plugins#install-a-plugin-using-maven-coordinates):

  Provide the Maven coordinates for the available artifacts and versions hosted on [Maven Central](https://search.maven.org/search?q=org.opensearch.plugin).
  {{< clipboard >}}
  ```yaml
  installList:
          - org.opensearch.plugin:opensearch-anomaly-detection:2.2.0.0
  ```
  {{< /clipboard >}}
{{< alert title="NOTE" color="primary" >}}
- Adding a new plug-in to the `plugins.installList` or removing a plug-in from the `plugins.installList` will result in restarting the OpenSearch related pods.
- To verify that a plug-in has installed successfully, make sure that no pod is in the CrashLoopBackOff state and the plug-in functionality is working fine.
- If there is any error during plug-in installation, then one of the OS master pods will go into the CrashLoopBackOff state, while other pods will still be in the Running state, and the OpenSearch cluster will be healthy and functional. Check the logs for the exact reason of the failure.
- Your environment must be able to connect to the Internet to access the provided plug-in URL or [Maven Central](https://search.maven.org/search?q=org.opensearch.plugin) to install the plug-in. In the case of an Internet issue, you might see SocketException or UnknownHostException exceptions in the logs. To resolve this issue, make sure that the pods are connected to the Internet.
- To be compatible, major, minor, and patch plug-in versions must match the OpenSearch major, minor, and patch versions. For example, plug-ins versions 2.3.0.x are compatible only with OpenSearch version 2.3.0.
{{< /alert >}}

For OpenSearch Dashboard, you can provide the plug-ins by defining the field [spec.components.opensearch-dashboards.plugins](/docs/reference/api/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.v1beta1.OpenSearchDashboardsComponent) in the Verrazzano custom resource.

#### Pre-built plug-ins for OpenSearch Dashboards
Here is a pre-built plug-in that is bundled with the OpenSearch Dashboard image: `indexManagementDashboards`

Here is a Verrazzano custom resource example to install plug-ins for the OpenSearch Dashboards:
{{< clipboard >}}
```yaml
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: custom-opensearch-example
spec:
  profile: dev
  components:
    opensearchDashboards:
      plugins:
        enabled: true
        installList:
          - <URL to OpenSearch Dashboard plugin ZIP file>
```
{{< /clipboard >}}
