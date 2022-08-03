---
title: "Jaeger Tracing"
linkTitle: Jaeger Tracing
description: "Configure Jaeger to capture application traces"
weight: 4
draft: false
---

Jaeger is a distributed tracing system used for monitoring and troubleshooting microservices.
For more information on Jaeger, see the [Jaeger website](https://www.jaegertracing.io/).

## Install Jaeger Operator

To install the Jaeger Operator, enable the `jaegerOperator` component in your Verrazzano custom resource. Here is
an example YAML file that enables the Jaeger Operator. Verrazzano installs the Jaeger Operator in the
`verrazzano-monitoring` namespace. If OpenSearch and Keycloak components are enabled in the Verrazzano custom resource,
then a default Jaeger instance is also created by the Jaeger Operator in the `verrazzano-monitoring` namespace.

```yaml
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: verrazzano
spec:
  profile: prod
  components:
    jaegerOperator:
      enabled: true
```
The Jaeger Operator will create `Service` custom resources for query and collection. After applying the Verrazzano
custom resource, listing Jaeger resources will show output similar to the following.
```
$ kubectl get services,deployments -l app.kubernetes.io/instance=jaeger-operator-jaeger -n verrazzano-monitoring

NAME                                                TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)                                  AGE
service/jaeger-operator-jaeger-collector            ClusterIP   10.96.120.223   <none>        9411/TCP,14250/TCP,14267/TCP,14268/TCP   79m
service/jaeger-operator-jaeger-collector-headless   ClusterIP   None            <none>        9411/TCP,14250/TCP,14267/TCP,14268/TCP   79m
service/jaeger-operator-jaeger-query                ClusterIP   10.96.209.196   <none>        16686/TCP,16685/TCP                      79m

NAME                                               READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/jaeger-operator-jaeger-collector   1/1     1            1           79m
deployment.apps/jaeger-operator-jaeger-query       1/1     1            1           79m
```

## Customize Jaeger

Verrazzano installs the Jaeger Operator and Jaeger using the
[jaeger-operator](https://github.com/jaegertracing/helm-charts/tree/main/charts/jaeger-operator) Helm chart.
Using Helm overrides specified in the Verrazzano custom resource, you can customize the installation configuration.
For more information about setting component overrides, see [Customizing the Chart Before Installing](https://helm.sh/docs/intro/using_helm/#customizing-the-chart-before-installing).

### Customize a Jaeger instance to use an external OpenSearch or Elasticsearch for storage

You can use the default Jaeger instance with an external OpenSearch cluster. The following example shows you how to
configure Jaeger Operator Helm overrides in the Verrazzano custom resource to use an external OpenSearch cluster
with a TLS CA certificate mounted from a volume and the user/password stored in a secret. For more details, see the
[Jaeger documentation](https://www.jaegertracing.io/docs/latest/operator/#external-elasticsearch).

1. Prior to configuring the external OpenSearch for Jaeger in the Verrazzano custom resource, create a secret containing
   the OpenSearch credentials and certificates in the `verrazzano-install` namespace. Jaeger will use these credentials
   to connect to OpenSearch.
   ```
   $ kubectl create secret generic jaeger-secret \
    --from-literal=ES_PASSWORD=<OPENSEARCH PASSWORD> \
    --from-literal=ES_USERNAME=<OPENSEARCH USERNAME> \
    --from-file=ca-bundle=<path to the file containing CA certs> \
    -n verrazzano-install
   ```
1. Use the Verrazzano custom resource to update the Jaeger resource:

```yaml
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: custom-jaeger-external-opensearch
spec:
  profile: prod
  components:
    jaegerOperator:
      overrides:
        - values:
            jaeger:
              create: false
              spec:
                strategy: production
                storage:
                  type: elasticsearch
                  options:
                    es:
                      # Enter your OpenSearch cluster endpoint here.
                      server-urls: <External OpenSearch URL>
                      index-prefix: jaeger
                      tls:
                        ca: /verrazzano/certificates/ca-bundle
                  secretName: jaeger-secret
                volumeMounts:
                  - name: certificates
                    mountPath: /verrazzano/certificates/
                    readOnly: true
                volumes:
                  - name: certificates
                    secret:
                      secretName: jaeger-secret
```

### Enable the Service Performance Monitoring experimental feature

To enable the Jaeger [Service Performance Monitoring](https://www.jaegertracing.io/docs/latest/spm/) experimental
feature in the default Jaeger instance created by Verrazzano, use the following Verrazzano custom resource. Verrazzano
sets `jaeger.spec.query.options.prometheus.server-url` to the Prometheus server URL managed by Verrazzano, if it exists.
To configure an external Prometheus server for your use case, override `jaeger.spec.query.options.prometheus.server-url`,
`jaeger.spec.query.options.prometheus.tls.enabled` and `jaeger.spec.query.options.prometheus.tls.ca` appropriately in
the Verrazzano custom resource. For more details, see the [Jaeger documentation](https://www.jaegertracing.io/docs/latest/deployment/#tls-support-1).

```yaml
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: custom-jaeger
spec:
  profile: prod
  components:
    jaegerOperator:
      overrides:
        - values:
            jaeger:
              spec:
                query:
                  metricsStorage:
                    type: prometheus
```

### Disable default Jaeger instance creation

To disable the default Jaeger instance created by Verrazzano, use the following Verrazzano custom resource:

```yaml
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: custom-jaeger
spec:
  profile: prod
  components:
    jaegerOperator:
      overrides:
        - values:
            jaeger:
              create: false
```

### Jaeger Operator Helm chart values that cannot be overridden

The following Jaeger Operator Helm values are not supported to be overridden in the Verrazzano custom resource:
- `nameOverride`
- `fullnameOverride`
- `serviceAccount.name`
- `ingress.enabled`
- `jaeger.spec.storage.dependencies.enabled`

If you try to override the above Helm values in the Verrazzano custom resource, the request will be rejected and an
error message returned.

**Note:** - Verrazzano does not support [Jaeger Spark dependencies](https://github.com/jaegertracing/spark-dependencies)
and hence the Helm chart value `jaeger.spec.storage.dependencies.enabled`, which is set to `false` for the Jaeger
instance managed by Verrazzano, cannot be overridden.

## Configure an application to export traces to Jaeger

The Jaeger agent sidecar is injected to application pods by the
`"sidecar.jaegertracing.io/inject": "true"` annotation. You may apply this annotation to namespaces or pod controllers,
such as Deployments. The subsequent snippet shows how to annotate an OAM Component for Jaeger agent injection.

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

## View traces on the Jaeger UI

After the installation has completed, you can use the Verrazzano Jaeger UI to view the traces.
For information on how to get the Verrazzano Jaeger UI URL and credentials, see [Access Verrazzano]({{< relref "/docs/access/" >}}).

## Configure the Istio mesh to use Jaeger tracing

You can view Istio mesh traffic by enabling Istio's distributed tracing integration. Traces from the Istio mesh provide observability on application traffic
that passes through Istio's ingress and egress gateways.

Istio tracing is disabled by default. To turn on traces, customize your Istio component like the following example:

```yaml
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: verrazzano
spec:
  profile: prod
  components:
    jaegerOperator:
      enabled: true
    istio:
      istioInstallArgs:
        - name: "meshConfig.enableTracing"
          value: "true"
```

After enabling tracing, Istio will automatically configure itself with the Jaeger endpoint in your cluster,
and any new Istio-injected pods will begin exporting traces to Jaeger. Existing pods require a restart
to pull the new Istio configuration and start sending traces.

Istio's default sampling rate is 1%, meaning 1 in 100 requests will be traced in Jaeger.
If you want a different sampling rate, configure your desired rate using the `meshConfig.defaultConfig.tracing.sampling` Istio installation argument.

```yaml
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: verrazzano
spec:
  profile: prod
  components:
    jaegerOperator:
      enabled: true
    istio:
      istioInstallArgs:
        - name: "meshConfig.enableTracing"
          value: "true"
        # 25% of Istio traces will be sampled.  
        - name: "meshConfig.defaultConfig.tracing.sampling"
          value: "25.0"
```

## Management of Jaeger indices in OpenSearch

To clean old Jaeger data from OpenSearch, Verrazzano uses the [index management](https://www.jaegertracing.io/docs/latest/operator/#elasticsearch-index-cleaner-job)
provided by Jaeger. By default, a cron job with the following default values is created to clean old traces. To
configure it to your use case, override the following Jaeger spec values in the Verrazzano custom resource with your
desired values.

```
storage:
  type: elasticsearch
  esIndexCleaner:
    enabled: true                                 // turn the cron job deployment on and off
    numberOfDays: 7                               // number of days to wait before deleting a record
    schedule: "55 23 * * *"                       // cron expression for it to run
```


