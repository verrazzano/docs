---
title: "Troubleshoot Prometheus Issues"
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

### Metrics queries no longer return metrics

If Prometheus storage reaches capacity, then metrics queries will no longer return results. Check the Prometheus logs.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl logs -l app.kubernetes.io/instance=prometheus-operator-kube-p-prometheus -n verrazzano-monitoring
```

</div>
{{< /clipboard >}}

If there are messages indicating that the disk is full, then it will be necessary to either expand the storage or free disk space. If the default storage class supports volume expansion,
then you can attempt to expand the volume.

Check if the default storage class allows volume expansion.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl get storageclass
```

</div>
{{< /clipboard >}}

If the default storage class allows expansion, then modify the persistent volume claim and the Prometheus resource storage request to use the larger size.

For example, to increase the storage to 100 Gi:

{{< clipboard >}}
<div class="highlight">

```
$ kubectl patch pvc prometheus-prometheus-operator-kube-p-prometheus-db-prometheus-prometheus-operator-kube-p-prometheus-0 -n verrazzano-monitoring \
   --type=merge -p '{"spec":{"resources":{"requests":{"storage":"100Gi"}}}}'

$ kubectl patch prometheus prometheus-operator-kube-p-prometheus -n verrazzano-monitoring \
   --type=merge -p '{"spec":{"storage":{"volumeClaimTemplate":{"spec":{"resources":{"requests":{"storage":"100Gi"}}}}}}}'
```

</div>
{{< /clipboard >}}

Alternatively, delete existing metrics data in the Prometheus pods to free space.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl exec statefulset.apps/prometheus-prometheus-operator-kube-p-prometheus -n verrazzano-monitoring -- rm -fr /prometheus/wal

$ kubectl rollout restart statefulset.apps/prometheus-prometheus-operator-kube-p-prometheus -n verrazzano-monitoring
```

</div>
{{< /clipboard >}}

For information on how to configure Prometheus data retention settings to avoid filling up persistent storage in the Prometheus pods,
see [Configure data retention settings]({{< relref "/docs/observability/monitoring/configure/prometheus#configure-data-retention-settings" >}}).
