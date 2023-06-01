---
title: "Troubleshoot Prometheus Issues"
description: "Common troubleshoot Prometheus issues that you"
weight: 5
draft: false
aliases:
  - /docs/troubleshooting/troubleshooting-prometheus
---

### Kubernetes cluster monitors are in a DOWN state
When viewing targets in the Prometheus console, some Kubernetes cluster monitors may be down (`kube-etcd`, `kube-proxy`, and such). This is likely caused by the configuration of the Kubernetes cluster
itself. Depending on the type of cluster, certain metrics may be disabled by default. Enabling metrics is cluster dependent; for details, refer to the documentation for your cluster type.

For example, to enable `kube-proxy` metrics on Kind clusters, edit the `kube-proxy` ConfigMap.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl edit cm/kube-proxy -n kube-system
```

</div>
{{< /clipboard >}}


Replace the `metricsBindAddress` value with the following and save the ConfigMap.
{{< clipboard >}}
<div class="highlight">

```
metricsBindAddress: 0.0.0.0:10249
```

</div>
{{< /clipboard >}}


Then, restart the `kube-proxy` pods.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl delete pod -l k8s-app=kube-proxy -n kube-system
```

</div>
{{< /clipboard >}}


For more information, see this GitHub [issue](https://github.com/prometheus-community/helm-charts/issues/204).

### Metrics Trait Service Monitor not discovered

Metrics Traits use Service Monitors which require a Service to collect metrics.
If your OAM workload is created with a Metrics Trait and no Ingress Trait, a Service might not be generated for your workload and will need to be created manually.

This troubleshooting example uses the `hello-helidon` application.

Verify a Service Monitor exists for your application workload.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get servicemonitors -n hello-helidon
```

</div>
{{< /clipboard >}}


Verify a Service exists for your application workload.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get services -n hello-helidon
```

</div>
{{< /clipboard >}}

If no Service exists, create one manually.
This example uses the default Prometheus port.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: v1
kind: Service
metadata:
  name: hello-helidon-service
  namespace: hello-helidon
spec:
  selector:
    app: hello-helidon
  ports:
    - name: tcp-hello-helidon
      port: 8080
      protocol: TCP
      targetPort: 8080
```

</div>
{{< /clipboard >}}

After you've completed these steps, you can [verify metrics collection]({{< relref "/docs/observability/monitoring/configure-metrics.md#verify-metrics-collection" >}}) has succeeded.
