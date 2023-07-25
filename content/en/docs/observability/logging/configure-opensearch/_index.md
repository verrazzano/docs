---
title: "Configure OpenSearch Clusters"
weight: 2
draft: false
aliases:
  - /docs/monitoring/logs
---

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


Verrazzano provides support for [Installation Profiles]({{< relref "/docs/setup/install/perform/profiles.md" >}}). The production profile (`prod`), which is the default, provides a 3-node OpenSearch and persistent storage for the VMI. The development profile (`dev`) provides a single node OpenSearch and no persistent storage for the VMI. The `managed-cluster` profile does not install OpenSearch or OpenSearch Dashboards in the local cluster; all logs are forwarded to the admin cluster's OpenSearch instance.

If you want the logs sent to an external OpenSearch, instead of the default VMI OpenSearch, specify `opensearchURL` and `opensearchSecret` in the [FluentdComponent]({{< relref "/docs/reference/vpo-verrazzano-v1beta1#install.verrazzano.io/v1beta1.FluentdComponent" >}}) configuration in your Verrazzano custom resource.

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

For information on OpenSearch, see the [Customize OpenSearch]({{< relref "/docs/observability/logging/configure-opensearch/opensearch" >}}).

## OpenSearch Dashboards
OpenSearch Dashboards is a visualization dashboard for the content indexed on an OpenSearch cluster.  Verrazzano creates a OpenSearch Dashboards deployment to provide a user interface for querying and visualizing the log data collected in OpenSearch.

To access the OpenSearch Dashboards, read [Access Verrazzano]({{< relref "/docs/setup/access/_index.md" >}}).

To see the records of an OpenSearch index or data stream through OpenSearch Dashboards, create an index pattern to filter for records under the desired data stream or index.  

For example, to see the log records of a WebLogic application deployed to the `todo-list` namespace, create an index pattern of `verrazzano-application-todo-*`.

![OpenSearch Dashboards](/docs/images/opensearch-dashboards-todo.png)
