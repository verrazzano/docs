---
title: "Logging"
linkTitle: Logging
description: "Learn about Verrazzano log collection and viewing"
weight: 2
draft: false
---

The Verrazzano logging stack consists of Fluentd, OpenSearch, and OpenSearch Dashboards components.

* Fluentd: a log aggregator that collects, processes, and formats logs from Kubernetes clusters.
* OpenSearch: a scalable search and analytics engine for storing Kubernetes logs.
* OpenSearch Dashboards: a visualization layer that provides a user interface to query and visualize collected logs.

As shown in the following diagram, logs written to stdout by a container running on Kubernetes are picked up by the kubelet service running on that node and written to `/var/log/containers`.

![Logging](/docs/images/logging.png)


## Fluentd sidecar
For components with multiple log streams or that cannot log to stdout, Verrazzano deploys a Fluentd sidecar which parses and translates the log stream.  The resulting log is sent to stdout of the sidecar container and then written to `/var/log/containers` by the kubelet service.

For example, in a WebLogic deployment, `AdminServer.log` is consumed, translated, and written to stdout by the Fluentd sidecar.  You can view these logs using `kubectl` on the container named `fluentd-stdout-sidecar`.
{{< clipboard >}}
<div class="highlight">

 ```
$ kubectl logs tododomain-adminserver \
    -n todo-list \
    -c fluentd-stdout-sidecar
```

</div>
{{< /clipboard >}}


The Verrazzano Fluentd Docker image comes with these plug-ins:

- [fluent-plugin-concat](https://github.com/fluent-plugins-nursery/fluent-plugin-concat)
- [fluent-plugin-dedot_filter](https://github.com/lunardial/fluent-plugin-dedot_filter)
- [fluent-plugin-detect-exceptions](https://github.com/GoogleCloudPlatform/fluent-plugin-detect-exceptions)
- [fluent-plugin-opensearch](https://docs.fluentd.org/output/opensearch)
- [fluent-plugin-grok-parser](https://github.com/fluent/fluent-plugin-grok-parser)
- [fluent-plugin-json-in-json-2](https://rubygems.org/gems/fluent-plugin-json-in-json-2)
- [fluent-plugin-kubernetes_metadata_filter](https://github.com/fabric8io/fluent-plugin-kubernetes_metadata_filter)
- [fluent-plugin-multi-format-parser](https://github.com/repeatedly/fluent-plugin-multi-format-parser)
- [fluent-plugin-parser-cri](https://github.com/fluent/fluent-plugin-parser-cri)
- [fluent-plugin-prometheus](https://github.com/fluent/fluent-plugin-prometheus)
- [fluent-plugin-record-modifier](https://github.com/repeatedly/fluent-plugin-record-modifier)
- [fluent-plugin-rewrite-tag-filter](https://github.com/fluent/fluent-plugin-rewrite-tag-filter)
- [fluent-plugin-systemd](https://github.com/fluent-plugin-systemd/fluent-plugin-systemd)
- [fluent-plugin-oci-logging](https://github.com/oracle/fluent-plugin-oci-logging)

The Verrazzano Fluentd Docker image also has two local default plug-ins, `kubernetes_parser` and `kubernetes_multiline_parser`.
These plug-ins help to parse Kubernetes management log files.

Here are example use cases for these plug-ins:
{{< clipboard >}}
<div class="highlight">

```
# ---- fluentd.conf ----
# kubernetes parser
<source>
  @type tail
  path ./kubelet.log
  read_from_head yes
  tag kubelet
  <parse>
     @type multiline_kubernetes
  </parse>
</source>

# kubernetes multi-line parser
<source>
  @type tail
  path ./kubelet.log
  read_from_head yes
  tag kubelet
  <parse>
     @type multiline_kubernetes
  </parse>
</source>
# ----   EOF      ----
```

</div>
{{< /clipboard >}}


## Fluentd DaemonSet
Verrazzano deploys a Fluentd DaemonSet which runs one Fluentd replica per node in the `verrazzano-system` namespace.
Each instance pulls logs from the node's `/var/log/containers` directory and writes them to the target OpenSearch data stream.
Verrazzano system applications receive special handling, and write their logs to the `verrazzano-system` data stream.
Verrazzano application logs are exported to a data stream based on the application's namespace, following this format: `verrazzano-application-<application namespace>`.

For example, `vmi-system-opensearchDashboards` logs written to `/var/log/containers` will be pulled by Fluentd and written to OpenSearch.  The logs are exported
to the `verrazzano-system` data stream, because `vmi-system-opensearchDashboards` is a Verrazzano system application. For a non-system application, if it is in the `myapp` namespace,
then its logs will be exported to the `verrazzano-application-myapp` data stream.

## OpenSearch
Verrazzano creates an OpenSearch cluster as the store and search engine for the logs processed by Fluentd.  Records written by Fluentd can be queried using the OpenSearch REST API.

For example, you can use `curl` to get all of the OpenSearch data streams. First, you must get the password for the `verrazzano` user and the host for the Verrazzano Monitoring Instance (VMI) OpenSearch.
{{< clipboard >}}
<div class="highlight">

```
$ PASS=$(kubectl get secret \
    --namespace verrazzano-system verrazzano \
    -o jsonpath={.data.password} | base64 \
    --decode; echo)
$ HOST=$(kubectl get ingress \
    -n verrazzano-system vmi-system-os-ingest \
    -o jsonpath={.spec.rules[0].host})

$ curl -ik \
   --user verrazzano:$PASS https://$HOST/_data_stream
```

</div>
{{< /clipboard >}}

To see all of the records for a specific data stream, do the following:
{{< clipboard >}}
<div class="highlight">

```
$ DATA_STREAM=verrazzano-application-todo-list

$ curl -ik \
    --user verrazzano:$PASS https://$HOST/$DATA_STREAM/_search?q=message:*
```

</div>
{{< /clipboard >}}


Verrazzano provides support for [Installation Profiles]({{< relref "/docs/setup/install/profiles.md" >}}). The production profile (`prod`), which is the default, provides a 3-node OpenSearch and persistent storage for the VMI. The development profile (`dev`) provides a single node OpenSearch and no persistent storage for the VMI. The `managed-cluster` profile does not install OpenSearch or OpenSearch Dashboards in the local cluster; all logs are forwarded to the admin cluster's OpenSearch instance.

If you want the logs sent to an external OpenSearch, instead of the default VMI OpenSearch, specify `opensearchURL` and `opensearchSecret` in the [Fluentd]({{< relref "/docs/reference/API/vpo-verrazzano-v1beta1#install.verrazzano.io/v1beta1.FluentdComponent" >}}) Component configuration in your Verrazzano custom resource.

The following is an example of a Verrazzano custom resource to send the logs to the OpenSearch endpoint `https://external-os.default.172.18.0.231.nip.io`.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: default
spec:
  components:
    fluentd:
      opensearchURL: https://external-os.default.172.18.0.231.nip.io
      opensearchSecret: external-os-secret
```

</div>
{{< /clipboard >}}

## OpenSearch Dashboards
OpenSearch Dashboards is a visualization dashboard for the content indexed on an OpenSearch cluster.  Verrazzano creates a OpenSearch Dashboards deployment to provide a user interface for querying and visualizing the log data collected in OpenSearch.

To access the OpenSearch Dashboards, read [Access Verrazzano]({{< relref "/docs/access/_index.md" >}}).

To see the records of an OpenSearch index or data stream through OpenSearch Dashboards, create an index pattern to filter for records under the desired data stream or index.  

For example, to see the log records of a WebLogic application deployed to the `todo-list` namespace, create an index pattern of `verrazzano-application-todo-*`.

![OpenSearch Dashboards](/docs/images/opensearch-dashboards-todo.png)

## Log rotation

We recommend configuring log rotation for OpenSearch using Index State Management (ISM) or a periodic job to purge or snapshot old records.
For information on configuring OpenSearch ISM, see the [ISM setup page]({{< relref "/docs/customize/opensearch#configure-index-state-management-policies" >}}).

A basic implementation of job-based log rotation (not using ISM) is provided in the following example, implemented using a Kubernetes CronJob.
To install the log rotation example on your cluster, save the snippet to a file and make the following modifications:

- Substitue the value of `OPENSEARCH_HOST` with your specific OpenSearch HTTPS endpoint.
- By default, the CronJob deletes the last 7 days of data. You may customize this by modifying the query in the ConfigMap.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: log-rotate
  namespace: verrazzano-system
  labels:
    app: log-rotate
spec:
  # Rotate logs every day at midnight
  schedule: "0 0 * * *"
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            app: log-rotate
          annotations:
            sidecar.istio.io/inject: "false"
        spec:
          containers:
          - name: log-rotate
            args:
            - /bin/sh
            - -c
            - /opt/script/rotate
            env:
            - name: "OPENSEARCH_HOST"
              value: "https://opensearch.vmi.system.default.172.18.0.151.nip.io"
            - name: OPENSEARCH_USER
              valueFrom:
                secretKeyRef:
                  key: username
                  name: verrazzano
                  optional: true
            - name: OPENSEARCH_PASSWORD
              valueFrom:
                secretKeyRef:
                  key: password
                  name: verrazzano
                  optional: true
            image: ghcr.io/oracle/oraclelinux:7-slim
            imagePullPolicy: IfNotPresent
            volumeMounts:
            - mountPath: /opt/script
              name: log-rotate          
          restartPolicy: OnFailure
          volumes:
          - configMap:
              defaultMode: 0777
              name: log-rotate
            name: log-rotate
---

apiVersion: v1
kind: ConfigMap
metadata:
  name: log-rotate
  namespace: verrazzano-system
  labels:
    app: log-rotate
data:
  rotate: |
    #!/bin/bash
    curl -v --silent -k -u "$OPENSEARCH_USER:$OPENSEARCH_PASSWORD" -X POST "$OPENSEARCH_HOST/verrazzano-*/_delete_by_query" -H 'Content-Type: application/json' -d'
    {
      "query": {
        "bool": {
          "filter": [
            {
              "range": {
                "@timestamp": {
                  "lt": "now-7d"
                }
              }
            }
          ]
        }
      }
    }
    '
```

</div>
{{< /clipboard >}}
