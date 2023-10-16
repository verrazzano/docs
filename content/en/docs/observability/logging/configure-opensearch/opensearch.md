---
title: "Customize OpenSearch"
description: "Customize your OpenSearch cluster configuration"
weight: 3
draft: false
aliases:
  - /docs/customize/elasticsearch
  - /docs/customize/opensearch
  - /docs/setup/customizing/opensearch
---

Verrazzano supports two cluster topologies for an OpenSearch cluster:
- A single-node cluster: master, ingest, and data roles performed by a single node.
- A multi-node cluster configuration with separate master, data, and ingest nodes.

For information about the default OpenSearch cluster configurations provided by Verrazzano, see [Installation Profiles]({{< relref "/docs/setup/install/perform/profiles.md" >}}).
## Plan cluster topology

Start with an initial estimate of your hardware needs. The following recommendations will provide you with initial, educated estimates, but for ideal sizing, you will need to test them with representative workloads, monitor their performance, and then reiterate.

#### Storage requirements

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

#### Number of data nodes

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

  For 192 GiB of storage, the vCPU cores required are four.


#### Shard size

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
You can [customize Prometheus]({{< relref "/docs/observability/monitoring/configure/prometheus.md" >}}) to enable Alertmanager and configure recommended alarms (add alert rules) to get insight into your OpenSearch cluster and take some actions proactively.

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
[spec.components.opensearch.nodes](/docs/reference/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.OpenSearchNode)
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
        - name: es-master
          replicas: 0
        - name: es-data
          replicas: 0
        - name: es-ingest
          replicas: 0
```
{{< /clipboard >}}

After Verrazzano is installed or upgraded, to change the default node topology, use the following two steps.
1. Add new node pools.
  {{< clipboard >}}
  ```yaml
  apiVersion: install.verrazzano.io/v1beta1
  kind: Verrazzano
  metadata:
    name: custom-opensearch-example
  spec:
    profile: prod
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
  ```
  {{< /clipboard >}}
2. Because you are providing your own topology, set the default node pool replicas to zero.
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
          - name: es-master
            replicas: 0
          - name: es-data
            replicas: 0
          - name: es-ingest
            replicas: 0
  ```
  {{< /clipboard >}}

Listing the pods and persistent volumes in the `verrazzano-logging` namespace for the previous configuration
shows that the expected nodes are running with the appropriate data volumes.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get pvc,pod -l opster.io/opensearch-cluster=opensearch -n verrazzano-logging

# Sample output
NAME                                                             STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS   AGE
persistentvolumeclaim/data-opensearch-master-0                   Bound    pvc-9ace042a-dd68-4975-816d-f2ca0dc4d9d8   50Gi       RWO            standard       5m22s
persistentvolumeclaim/data-opensearch-master-1                   Bound    pvc-8bf68c2c-235e-4bd5-8741-5a5cd3453934   50Gi       RWO            standard       5m21s
persistentvolumeclaim/data-opensearch-master-2                   Bound    pvc-da8a48b1-5762-4669-98f0-8479f30043fc   50Gi       RWO            standard       5m21s
persistentvolumeclaim/data-opensearch-data-ingest-0              Bound    pvc-7ad9f275-632b-4aac-b7bf-c5115215937c   100Gi      RWO            standard       5m23s
persistentvolumeclaim/data-opensearch-data-ingest-1              Bound    pvc-8a293e51-2c20-4cae-916b-1ce46a780403   100Gi      RWO            standard       5m23s
persistentvolumeclaim/data-opensearch-data-ingest-2              Bound    pvc-0025fcef-1d8c-4307-977c-3921545c6730   100Gi      RWO            standard       5m22s

NAME                                                   READY   STATUS     RESTARTS   AGE
pod/opensearch-data-ingest-0                           2/2     Running    0          5m21s
pod/opensearch-data-ingest-1                           2/2     Running    1          5m21s
pod/opensearch-data-ingest-2                           2/2     Running    0          5m21s
pod/opensearch-dashboards-56d845466c-9xsrv             2/2     Running    0          5m21s
pod/opensearch-master-0                                2/2     Running    0          5m21s
pod/opensearch-master-1                                2/2     Running    0          5m21s
pod/opensearch-master-2                                2/2     Running    0          5m21s
```

</div>
{{< /clipboard >}}

Running the command `kubectl describe pod -n verrazzano-logging opensearch-data-ingest-0` shows the
requested amount of memory.
{{< clipboard >}}
<div class="highlight">

```
Containers:
  opensearch:
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
- `vz-application`: Manages the data in the application-related indices having the pattern, `verrazzano-application*`.

  ![vz-ism-policy](/docs/images/vz-ism-policy.png)

Both ISM policies have the same configuration, consisting of two states:
- **Hot**: This is the default state. If the primary shard size is greater than 5 GB or the index age is greater than 21 days, then the index will be rolled over. Fourteen days after the index has rolled over, it will transition to the `Delete` state.
- **Delete**: In this state, the index will be deleted. Fourteen days after being rolled over, the indices will reach this state.


## Override default ISM policies
The default ISM policies may not be suitable depending on the rate at which your OpenSearch cluster is ingesting data. Therefore, you may need to override the default ISM policies to meet your requirements.

The `vz-system` and `vz-application` policies are immutable and any change to these policies will be reverted immediately. However, the following two methods will override this behavior:
- **Disable default policies**: You can disable the default policies by setting the flag [spec.components.opensearch.disableDefaultPolicy](/docs/reference/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.OpenSearchComponent) to `true` in the Verrazzano CR. This will delete the default ISM policies and remove the policies from indices that are ingesting data. However, the deleted policies are not removed from older indices. To manually remove the policies from older indices, see [Remove policy from index](https://opensearch.org/docs/latest/im-plugin/ism/api/#remove-policy-from-index).
- **Override default policies**: Both these default policies have a zero (`0`) priority. You can override the default policies by creating policies with `policy.ism_template.priority` greater than `0` for same index pattern. To configure your own policies, see [Configure ISM Policies](/docs/observability/logging/configure-opensearch/opensearch/#configure-ism-policies).

{{< alert title="NOTE" color="primary" >}}
- Avoid creating policies with policy IDs `vz-system` or `vz-application` because they are reserved for Verrazzano default policies names. In the Verrazzano CR, by default, if the flag [spec.components.opensearch.disableDefaultPolicy](/docs/reference/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.OpenSearchComponent) is set to `false`, then policies that are created with these names will be overridden with the default ISM policies, .
- The default policy will be applied to the newly created indices and the indices which are ingesting data. To manually attach the new policies to the older indices, see [Step 2: Attach policies to indexes](https://opensearch.org/docs/latest/im-plugin/ism/index/#step-2-attach-policies-to-indexes).
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

**NOTE**: There might be a delay of a few minutes before you see the policy in OpenSearch. 

Also note that the ISM policy created using the Verrazzano custom resource contains a minimal set of configurations. To create a more detailed ISM policy,
you can use the OpenSearch REST API. To create a policy using the OpenSearch API, do the following:

{{< clipboard >}}

```bash
$ PASS=$(kubectl get secret \
    --namespace verrazzano-system verrazzano \
    -o jsonpath={.data.password} | base64 \
    --decode; echo)

$ HOST=$(kubectl get ingress \
    -n verrazzano-system opensearch \
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

## Override the default index template

Verrazzano provides a default index template, `verrazzano-data-stream`. For creating an index, the default index template has a few predefined settings, like the number of shards and replicas, dynamic mappings for fields, and such. However, you can override the default index template and use your own, preferred index template.

To do that, you need to copy the contents of the default index template and change the settings, as desired, and then create your index template with a higher priority so that the new template will override the default one.

You can use the OpenSearch Dev Tools Console to send given queries to OpenSearch. To open the console, select Dev Tools on the main OpenSearch Dashboards page and write your queries in the editor pane on the left side of the console.

To get the existing, default template:
{{< clipboard >}}
```yaml
$ GET /_index_template/verrazzano-data-stream
```
{{< /clipboard >}}

### Override default number of shards and replicas

In initial Verrazzano v1.5 installations (not upgrades), the default index template creates one shard and one replica for each index. (In previous and upgrade installations, it creates five shards and one replica). To change the default number of shards and replicas, get the default index template, change the number of shards and replicas to the desired values, and create a new index template with higher priority.

Here is an example that creates a new index template and changes the number of shards to `3` and replicas to `2`.
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

### Override default mappings and field types
The default index template uses dynamic mapping to store all fields as `text` and `keyword`. For your application, if you want to store a field as a different type, get the default index template, change the mappings for the desired fields, and then create a new index template with a higher priority.

Here is an example that creates a new index template, for applications in the `myapp*` namespace, which dynamically maps all long fields to integers and explicitly maps `age` and `ip_address` fields as `integer` and `ip` respectively.

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
              "number_of_shards" : "1",
              "auto_expand_replicas" : "0-1",
              "number_of_replicas" : "0"
            }
          },
          "mappings" : {
            "dynamic_templates" : [
              {
                "long_as_int" : {
                  "mapping" : {
                    "type" : "integer"
                  },
                  "match_mapping_type" : "long"
                }
              },
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
              },
              "age" : {
                "type" : "integer"
              },
              "ip_address" : {
                "type" : "ip",
                "ignore_malformed" : true
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
With this example, new indices that match the `verrazzano-application-myapp*` index pattern will store `age` and `ip_address` fields as `integer` and `ip` instead of `text`. Also, long data fields will be stored as `integer`. For more information, see [Mappings and field types](https://opensearch.org/docs/latest/field-types/index/) in the OpenSearch documentation.

### Configure pre-existing indices after overriding the default index template
For your application, if you already have indices created by OpenSearch that are based on the default index template, then complete the steps in the following sections to configure them.

#### Rollover data stream
The mappings for existing indices cannot be changed, so you will need to rollover the data stream for your application to create an index. Then, OpenSearch will start indexing data based on the newer template that you created.

To rollover the data stream:

{{< clipboard >}}
```yaml
POST /verrazzano-application-myapp/_rollover
```
{{< /clipboard >}}

**NOTE**: The default ISM policy that Verrazzano provides regularly rolls over the index after meeting certain conditions, so there might not be a requirement to manually rollover the index.

#### Refresh the index pattern

To see the updated mappings for your fields on the Discover page, you need to refresh the index pattern for your application.

To refresh the index pattern:
1. On the main OpenSearch Dashboards page, under the Management section, navigate to Stack Management in the Dock.
2. Then, go to Index Pattern > `verrazzano-application*`. If you have created a separate index pattern for your application, then select that.
3. Click the Refresh field list icon in the upper, right-hand side of the page.

![refresh-field-list-icon](/docs/images/refresh-field-list-icon.png)

#### Reindex indices

After refreshing the field list, if you see a warning about a mapping conflict, you need to reindex your previous indices. The mapping conflict arises because the previous indices have different mappings for fields than the newer indices, which were created based on the new index template with different mappings.

To reindex previous indices:

{{< clipboard >}}
```yaml
POST _reindex
{
  "conflicts" : "proceed",
   "source" : {
      "index" : [
         ".ds-verrazzano-application-myapp-000001"
      ]
   },
   "dest" : {
      "index" : "verrazzano-application-myapp",
      "op_type" : "create"
   }
}
```
{{< /clipboard >}}

Under source, list all the previous indices that were created based on the default index template. After reindexing is complete, [Refresh the index pattern](#refresh-the-index-pattern) again. For more information, see [Reindex data](https://opensearch.org/docs/latest/im-plugin/reindex-data/) in the OpenSearch documentation.

## Install OpenSearch and OpenSearch Dashboards plug-ins
Verrazzano supports OpenSearch and OpenSearch Dashboards plug-in installation by providing plug-ins in the Verrazzano custom resource.
To install plug-ins for OpenSearch, you define the field [spec.components.opensearch.plugins](/docs/reference/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.OpenSearchComponent) in the Verrazzano custom resource.

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
          - https://repo1.maven.org/maven2/org/opensearch/plugin/opensearch-anomaly-detection/2.3.0.0/opensearch-anomaly-detection-2.3.0.0.zip
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
- `opensearch-alerting`
- `opensearch-index-management`
- `opensearch-job-scheduler`
- `opensearch-notifications`
- `opensearch-notifications-core`
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
- If there is any error during plug-in installation, then one of the OpenSearch master pods will go into the CrashLoopBackOff state, while other pods will still be in the Running state, and the OpenSearch cluster will be healthy and functional. Check the logs for the exact reason of the failure.
- Your environment must be able to connect to the internet to access the provided plug-in URL or [Maven Central](https://search.maven.org/search?q=org.opensearch.plugin) to install the plug-in. In the case of an internet issue, you might see SocketException or UnknownHostException exceptions in the logs. To resolve this issue, make sure that the pods are connected to the internet.
- To be compatible, major, minor, and patch plug-in versions must match the OpenSearch major, minor, and patch versions. For example, plug-ins versions 2.3.0.x are compatible only with OpenSearch version 2.3.0.
{{< /alert >}}

For OpenSearch Dashboard, you can provide the plug-ins by defining the field [spec.components.opensearch-dashboards.plugins](/docs/reference/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.v1beta1.OpenSearchDashboardsComponent) in the Verrazzano custom resource.

#### Pre-built plug-ins for OpenSearch Dashboards
Here are pre-built plug-ins that are bundled with the OpenSearch Dashboards image:
- `alertingDashboards`
- `indexManagementDashboards`
- `notificationsDashboards`

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
          - <URL to OpenSearch Dashboards plug-in ZIP file>
```
{{< /clipboard >}}

## Add OpenSearch users
If you want to create additional users, other than the default OpenSearch user, then follow these instructions.
1. First, make sure that the user doesn't already exist. To get the existing users:

   {{< clipboard >}}
   ```yaml
   $ GET _plugins/_security/api/internalusers/
   ```
   {{< /clipboard >}}

2. Create a new user and backend role in Keycloak and then associate the role with the user. Also asscociate the role `vz_api_access` to the newly created user.

3. Create a new OpenSearch role for the user created in Step 2. Here is a custom resource example to create a custom role.

   {{< clipboard >}}
   ```yaml
   apiVersion: opensearch.opster.io/v1
   kind: OpensearchRole
   metadata:
     name: custom-role
     namespace: verrazzano-logging
   spec:
     opensearchCluster:
       name: opensearch
     clusterPermissions:
       - "cluster:monitor/main"
       - "cluster:monitor/health"
     indexPermissions:
     - indexPatterns:
       - verrazzano*
       allowedActions:
       - index
       - read
   ```
   {{< /clipboard >}}

   For the permissions that you can set, refer to [Opensearch Permissions]({{<opensearch_docs_url>}}/security/access-control/permissions/).

4. If you want to use actionGroups in allowedActions, then see the following example to create an ActionGroup custom resource.

   {{< clipboard >}}
   ```yaml
   apiVersion: opensearch.opster.io/v1
   kind: OpensearchActionGroup
   metadata:
     name: custom-action-group
     namespace: verrazzano-logging
   spec:
     opensearchCluster:
       name: opensearch
     allowedActions:
       - index
       - read
     type: index
     description: Custom action group
   ```
   {{< /clipboard >}}

5. After creating the user and roles, link them all together using an OpensearchUserRoleBinding custom resource. The following is a custom resource example to create a RoleBinding that binds the user `custom-user` and backend role `custom-role` created in Step 2 and OpenSearch role `custom-role` created in Step 3.

   {{< clipboard >}}
   ```yaml
   apiVersion: opensearch.opster.io/v1
   kind: OpensearchUserRoleBinding
   metadata:
     name: custom-rb
     namespace: verrazzano-logging
   spec:
     opensearchCluster:
       name: opensearch
     users:
     - custom-user
     backendRoles:
     - custom-role
     roles:
     - custom-role
   ```
   {{< /clipboard >}}
