---
title: "Configure Fluentd for Log Collection"
description: "Configure Fluentd for log collection"
weight: 3
draft: false
aliases:
  - /docs/monitoring/logs
---

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

For example, `vmi-system-osd` logs written to `/var/log/containers` will be pulled by Fluentd and written to OpenSearch.  The logs are exported
to the `verrazzano-system` data stream, because `vmi-system-osd` is a Verrazzano system application. For a non-system application, if it is in the `myapp` namespace,
then its logs will be exported to the `verrazzano-application-myapp` data stream.
