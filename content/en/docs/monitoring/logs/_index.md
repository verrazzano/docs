---
title: "Logging"
linkTitle: Logging
description: "Learn about Verrazzano log collection and viewing"
weight: 1
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
 ```
$ kubectl logs tododomain-adminserver \
    -n todo-list \
    -c fluentd-stdout-sidecar
```

The Verrazzano Fluentd Docker image comes with these plug-ins:

- [fluent-plugin-concat](https://github.com/fluent-plugins-nursery/fluent-plugin-concat)
- [fluent-plugin-dedot_filter](https://github.com/lunardial/fluent-plugin-dedot_filter)
- [fluent-plugin-detect-exceptions ](https://github.com/GoogleCloudPlatform/fluent-plugin-detect-exceptions)
- [fluent-plugin-elasticsearch](https://docs.fluentd.org/output/elasticsearch)
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

For more details, see the [Fluentd plugins](https://github.com/verrazzano/fluentd-kubernetes-daemonset/tree/oracle-build-from-source-v1.12/docker-image/v1.12/oraclelinux-elasticsearch7/plugins) folder.

## Fluentd DaemonSet
Verrazzano deploys a Fluentd DaemonSet which runs one Fluentd replica per node in the `verrazzano-system` namespace.
Each instance pulls logs from the node's `/var/log/containers` directory and writes them to the target OpenSearch index.  The index name is based on the namespace associated with the record, using this format: `verrazzano-namespace-<record namespace>`.

For example, `vmi-system-kibana` logs written to `/var/log/containers` will be pulled by Fluentd and written to OpenSearch.  The index used is named `verrazzano-namespace-verrazzano-system` because the VMI runs in the `verrazzano-system` namespace.

The same approach is used for both system and application logs.
## OpenSearch
Verrazzano creates an OpenSearch deployment as the store and search engine for the logs processed by Fluentd.  Records written by Fluentd can be queried using the OpenSearch REST API.

For example, you can use `curl` to get all of the OpenSearch indexes. First, you must get the password for the `verrazzano` user and the host for the VMI OpenSearch.
```
$ PASS=$(kubectl get secret \
    --namespace verrazzano-system verrazzano \
    -o jsonpath={.data.password} | base64 \
    --decode; echo)
$ HOST=$(kubectl get ingress \
    -n verrazzano-system vmi-system-es-ingest \
    -o jsonpath={.spec.rules[0].host})

$ curl -ik \
   --user verrazzano:$PASS https://$HOST/_cat/indices
```

To see all of the records for a specific index, do the following:
```
$ INDEX=verrazzano-namespace-todo-list

$ curl -ik \
    --user verrazzano:$PASS https://$HOST/$INDEX/_doc/_search?q=message:*
```

Verrazzano provides support for [Installation Profiles]({{< relref "/docs/setup/install/profiles.md" >}}). The production profile (`prod`), which is the default, provides a 3-node OpenSearch and persistent storage for the Verrazzano Monitoring Instance (VMI). The development profile (`dev`) provides a single node OpenSearch and no persistent storage for the VMI. The `managed-cluster` profile does not install OpenSearch or OpenSearch Dashboards in the local cluster; all logs are forwarded to the admin cluster's OpenSearch instance.

If you want the logs sent to an external OpenSearch, instead of the default VMI OpenSearch, specify `elasticsearchURL` and `elasticsearchSecret` in the [Fluentd]({{< relref "/docs/reference/API/Verrazzano/Verrazzano.md#fluentd-component" >}}) Component configuration in your Verrazzano custom resource.

The following is an example of a Verrazzano custom resource to send the logs to the OpenSearch endpoint `https://external-es.default.172.18.0.231.nip.io`.
```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: default
spec:
  components:
    fluentd:
      elasticsearchURL: https://external-es.default.172.18.0.231.nip.io
      elasticsearchSecret: external-es-secret
```
## OpenSearch Dashboards
OpenSearch Dashboards is a visualization dashboard for the content indexed on an OpenSearch cluster.  Verrazzano creates a OpenSearch Dashboards deployment to provide a user interface for querying and visualizing the log data collected in OpenSearch.

To access the OpenSearch Dashboards console, read [Access Verrazzano]({{< relref "/docs/operations/_index.md" >}}).

To see the records of an OpenSearch index through OpenSearch Dashboards, create an index pattern to filter for records under the desired index.  

For example, to see the log records of a WebLogic application deployed to the `todo-list` namespace, create an index pattern of `verrazzano-namespace-todo-*`.

![OpenSearch Dashboards](/docs/images/opensearch.png)
