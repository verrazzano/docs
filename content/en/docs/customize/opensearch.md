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
- A single-node cluster (master, ingest, and data roles performed by a single node).
- A multi-node cluster configuration with separate master, data, and ingest nodes.

[Installation Profiles]({{< relref "/docs/setup/install/profiles.md" >}}) describes the default OpenSearch cluster
configurations provided by Verrazzano.  

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
   <code>

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
   </code>
</div>
{{< /clipboard >}}

Running the command `kubectl describe pod -n verrazzano-system vmi-system-data-ingest-0-5485dcd95d-rkhvk` shows the
requested amount of memory.
{{< clipboard >}}
<div class="highlight">
   <code>

```
Containers:
  os-data:
    ...
    Requests:
      memory:   1Gi
```
   </code>
</div>
{{< /clipboard >}}

## Configure Index State Management policies

[Index State Management]({{<opensearch_docs_url>}}/im-plugin/ism/index/) (ISM) policies configure OpenSearch to manage the data in your indices.
You can use policies to automatically rollover and prune old data, preventing your OpenSearch
cluster from running out of disk space.

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
            minSize: 10Gb
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

**NOTE:** The ISM policy created using the Verrazzano custom resource contains a minimal set of configurations. To create a more detailed ISM policy,
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

## Default ISM policies
To help you manage issues, such as low disk space, the following two ISM policies are created by default:
- `vz-system`: Manages the data in the Verrazzano system indices.

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
- **Override default policies**: Both these default policies have a zero (`0`) priority. You can override the default policies by creating policies with `policy.ism_template.priority` greater than `0`.

{{< alert title="NOTE" color="warning" >}}
- Avoid creating policies with policy IDs `vz-system` or `vz-application`. In the Verrazzano CR, by default, policies that are created with these names will be overridden with the ISM policies, if the flag [spec.components.opensearch.disableDefaultPolicy](/docs/reference/api/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.OpenSearchComponent) is set to `false`.
- The default policy will be applied only to the newly created indices. To manually attach the new policies to the older indices, see [Step 2: Attach policies to indexes](https://opensearch.org/docs/latest/im-plugin/ism/index/#step-2-attach-policies-to-indexes).
{{< /alert >}}

## Default index patterns
The default index patterns, `verrazzano-system` and `verrazzano-application*`, are created by Verrazzano. These index patterns are immutable. Changes to these index patterns will be lost because Verrazzano will reconcile and replace them with the default ISM policies.

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
There are three ways to define a plug-in in the `plugins.installList`:
- [Define a plug-in by name](https://opensearch.org/docs/latest/opensearch/install/plugins#install-a-plugin-by-name):

  There are some pre-built [additional plug-ins](https://opensearch.org/docs/latest/opensearch/install/plugins#additional-plugins) that you can install by name.
  {{< clipboard >}}

  ```yaml
  installList:
          - analysis-icu
  ```
  {{< /clipboard >}}
- [Define a plug-in from a remote ZIP file](https://opensearch.org/docs/latest/opensearch/install/plugins#install-a-plugin-from-a-zip-file):

  Provide the URL to a remote ZIP file that contains the required plug-in.
  {{< clipboard >}}

  ```yaml
  installList:
          - https://repo1.maven.org/maven2/org/opensearch/plugin/opensearch-anomaly-detection/2.2.0.0/opensearch-anomaly-detection-2.2.0.0.zip
  ```
  {{< /clipboard >}}
- [Define a plug-in using Maven coordinates](https://opensearch.org/docs/latest/opensearch/install/plugins#install-a-plugin-using-maven-coordinates):

  Provide the Maven coordinates for the available artifacts and versions hosted on [Maven Central](https://search.maven.org/search?q=org.opensearch.plugin).
  {{< clipboard >}}
  ```yaml
  installList:
          - org.opensearch.plugin:opensearch-anomaly-detection:2.2.0.0
  ```
  {{< /clipboard >}}
{{< alert title="NOTE" color="warning" >}}
 - Your environment must be able to connect to the Internet to access the provided plug-in URL or [Maven Central](https://search.maven.org/search?q=org.opensearch.plugin) to install the plug-in. If there is any error during plug-in installation, then the OS pods (one per deployment) will go into the CrashLoopBackOff state. Check the logs for the exact reason of the failure. In the case of an Internet issue, you might see SocketException or UnknownHostException exceptions in the logs. To resolve this issue, make sure that the pods are connected to the Internet.
 - Adding a new plug-in in the `plugins.installList` or removing a plug-in from the `plugins.installList` will result in restarting the OpenSearch related pods.
 - To be compatible, major, minor, and patch plug-in versions must match OpenSearch major, minor, and patch versions. For example, plug-ins versions 2.3.0.x are compatible only with OpenSearch version 2.3.0.
{{< /alert >}}

For OpenSearch Dashboard, you can provide the plug-ins by defining the field [spec.components.opensearch-dashboards.plugins](/docs/reference/api/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.v1beta1.OpenSearchDashboardsComponent) in the Verrazzano custom resource.

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