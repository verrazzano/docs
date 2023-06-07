---
title: "Capture Trace Spans"
linkTitle: Capture Trace Spans
description: "Configure applications to export traces to Jaeger"
weight: 4
draft: false
aliases:
  - /docs/monitoring/tracing/jaeger-tracing
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