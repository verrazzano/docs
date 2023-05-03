---
title: "Capture Trace Spans"
linkTitle: Capture Trace Spans
description: "Configure applications to export traces to Jaeger"
weight: 4
draft: false
---

The Jaeger agent sidecar is injected to application pods by the
`"sidecar.jaegertracing.io/inject": "true"` annotation. You may apply this annotation to namespaces or pod controllers,
such as Deployments. The subsequent snippet shows how to annotate an OAM Component for Jaeger agent injection.
{{< clipboard >}}

```yaml
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: example-component
spec:
  workload:
    apiVersion: core.oam.dev/v1alpha2
    kind: ContainerizedWorkload
    metadata:
      name: example-workload
      annotations:
        # The component's Deployment will carry the Jaeger annotation.
        "sidecar.jaegertracing.io/inject": "true"
```
{{< /clipboard >}}

If you have multiple Jaeger instances in your cluster, specify the name of the Jaeger instance to which you intend to
send the traces, as a value for the annotation `sidecar.jaegertracing.io/inject`. For more details,
see the [Jaeger documentation](https://www.jaegertracing.io/docs/{{<jaeger_doc_version>}}/operator/#auto-injecting-jaeger-agent-sidecars).

**NOTE**: Using the Jaeger agent is not supported in Helidon 3.x. To use Jaeger tracing,
the Helidon application should connect directly to the Jaeger collector. See the following example YAML file, where
`"TRACING_HOST"` is set to `"jaeger-operator-jaeger-collector.verrazzano-monitoring"` and `"TRACING_PORT"` to `"9411"`.
For [Jaeger tracing in a multicluster Verrazzano environment](#jaeger-tracing-in-a-multicluster-verrazzano-environment),
set the `"TRACING_HOST"` to `"jaeger-verrazzano-managed-cluster-collector.verrazzano-monitoring.svc.cluster.local"`.


{{< clipboard >}}

```yaml
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: hello-helidon-component
spec:
  workload:
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: VerrazzanoHelidonWorkload
    metadata:
      name: hello-helidon-workload
      labels:
        app: hello-helidon
        version: v1
    spec:
      deploymentTemplate:
        metadata:
          name: hello-helidon-deployment
        podSpec:
          containers:
            - name: hello-helidon-container
              image: "ghcr.io/verrazzano/example-helidon-greet-app-v1:1.0.0-1-20220513221156-7da0d32"
              env:
                - name: "TRACING_SERVICE"
                  value: "hello-helidon"
                - name: "TRACING_PORT"
                  value: "9411"
                - name: "TRACING_HOST"
                  value: "jaeger-operator-jaeger-collector.verrazzano-monitoring"
              ports:
                - containerPort: 8080
                  name: http
```
{{< /clipboard >}}


### Use Jaeger tracing in a multicluster Verrazzano environment

If the Jaeger Operator component is enabled in the managed cluster, after successful registration with the admin cluster,
a Jaeger collector service runs in the managed cluster, which exports the traces to the OpenSearch
storage configured in the admin cluster.

**NOTE**: Traces are exported to the admin cluster only when the Jaeger instance in the admin cluster is configured with the OpenSearch storage.

Listing Jaeger resources in the managed cluster shows output similar to the following.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get jaegers -n verrazzano-monitoring
```
</div>
{{< /clipboard >}}
```
#sample output
NAME                                STATUS    VERSION   STRATEGY     STORAGE         AGE
jaeger-verrazzano-managed-cluster   Running   1.34.1    production   opensearch      11m
```

#### Configure the Istio mesh in a managed cluster to export Jaeger traces to the admin cluster

To export the Istio mesh traces in the managed cluster to the admin cluster, set `meshConfig.defaultConfig.tracing.zipkin.address`
to the Jaeger Collector URL created in the managed cluster that exports the traces to the OpenSearch
storage configured in the admin cluster.

Configure the Istio mesh on the managed cluster at the time of the Verrazzano installation, as follows:
{{< clipboard >}}

```yaml
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: verrazzano
spec:
  profile: managed-cluster
  components:
    jaegerOperator:
      enabled: true
    istio:
      overrides:
      - values:
          apiVersion: install.istio.io/v1alpha1
          kind: IstioOperator
          spec:
            meshConfig:
              enableTracing: true
              defaultConfig:
                tracing:
                  zipkin:
                    address: jaeger-verrazzano-managed-cluster-collector.verrazzano-monitoring.svc.cluster.local.:9411
```
{{< /clipboard >}}
