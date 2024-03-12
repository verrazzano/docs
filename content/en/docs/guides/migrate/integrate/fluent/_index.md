---
title: "Fluentd and Fluent Bit"
weight: 1
draft: false
---
This document shows you how to integrate Fluentd and Fluent Bit with other OCNE components.

## Network policies

## Prometheus

Follow the example, [Configure the namespace ConfigSelector]({{< relref "docs/guides/migrate/install/fluent/_index.md#configure-the-namespace-configselector" >}}), to add a Helm override for the namespace config label selector.

Then, create the following ServiceMonitor resource in the `monitoring` namespace.

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
