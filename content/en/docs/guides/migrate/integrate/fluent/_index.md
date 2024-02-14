---
title: "Fluentd and Fluent Bit"
weight: 1
draft: false
---
This document shows you how to integrate Fluentd and Fluent Bit with other OCNE components.

## Network Policies
## Prometheus

Follow [fluent operator helm override recipe]({{< relref "docs/guides/migrate/install/prometheus/_index.md#configuration-to-allow-prometheus-to-scrape-metrics" >}}) to configure overrides for prometheus to scrape metrics.

Then, create the following ServiceMonitor resource in the `monitoring` namespace

{{< clipboard >}}
<div class="highlight">

```
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: fluentbit
  namespace: monitoring
  labels:
    release: prometheus-operator
spec:
  namespaceSelector:
    matchNames:
    - logging
  selector:
    matchLabels:
      app.kubernetes.io/name: "fluent-bit"
  endpoints:
    - path: /metrics
      targetPort: metrics
      enableHttp2: false
      scheme: http
```

</div>
{{< /clipboard >}}
