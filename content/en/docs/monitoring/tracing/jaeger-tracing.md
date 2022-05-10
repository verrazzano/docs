---
title: "Jaeger Tracing"
linkTitle: Jaeger Tracing
description: "Configure Jaeger to capture application traces"
weight: 1
draft: false
---

Jaeger is a distributed tracing system used for monitoring and troubleshooting microservices. 
For more information on Jaeger, visit the [Jaeger website](https://www.jaegertracing.io/).

## Install Jaeger Operator

To install the Jaeger Operator, enable the `jaegerOperator` component in your Verrazzano resource. Here is
an example YAML file that enables the Jaeger Operator.

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

## Install Jaeger using the Jaeger Operator

Jaeger is installed using the Jaeger Custom Resource Definition. The following example shows you how to install Jaeger inside the Istio mesh using the 
Verrazzano system OpenSearch cluster as a tracing backend.

Before creating the Jaeger instance, create a secret containing the OpenSearch user name and password.
Jaeger will use these credentials to connect to OpenSearch:

```
$ kubectl create secret generic jaeger-secret \
  --from-literal=ES_PASSWORD=<OPENSEARCH PASSWORD> \
  --from-literal=ES_USERNAME=<OPENSEARCH USERNAME> \
  -n verrazzano-system
```

Use the following YAML to create the Jaeger resource:

```yaml
apiVersion: jaegertracing.io/v1
kind: Jaeger
metadata:
  name: verrazzano-prod
  namespace: verrazzano-system
spec:
  annotations:
    sidecar.istio.io/inject: "true"
  strategy: production
  storage:
    # Jaeger Elasticsearch storage is compatible with Verrazzano OpenSearch.
    type: elasticsearch
    esIndexCleaner:
      enabled: false
      numberOfDays: 7
      schedule: "* * * * *"
    options:
      es:
        # Enter your OpenSearch cluster endpoint here.
        server-urls: https://elasticsearch.vmi.system.default.172.18.0.151.nip.io
        index-prefix: jaeger
        tls:
          ca: /verrazzano/certificates/ca.crt
    secretName: jaeger-secret
  volumeMounts:
    - name: certificates
      mountPath: /verrazzano/certificates/
      readOnly: true
  volumes:
    - name: certificates
      secret:
        # Jaeger should use the client TLS secret for OpenSearch. This is the default secret name for Verrazzano OpenSearch.
        secretName: system-tls-es-ingest
```

The Jaeger Operator will create services for query and collection. After applying the example resource, you should see similar output by listing 
Jaeger resources:
```
$ kubectl get services,deployments -l app.kubernetes.io/instance=verrazzano-prod -n verrazzano-system

NAME                                         TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)                                  AGE
service/verrazzano-prod-collector            ClusterIP   10.96.76.108   <none>        9411/TCP,14250/TCP,14267/TCP,14268/TCP   52m
service/verrazzano-prod-collector-headless   ClusterIP   None           <none>        9411/TCP,14250/TCP,14267/TCP,14268/TCP   52m
service/verrazzano-prod-query                ClusterIP   10.96.205.8    <none>        16686/TCP,16685/TCP                      52m

NAME                                        READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/verrazzano-prod-collector   1/1     1            1           52m
deployment.apps/verrazzano-prod-query       1/1     1            1           52m
```

## Configure an application to export traces to Jaeger

If your application is configured to use tracing libraries, or in the Istio mesh, you can instruct Jaeger to export those traces using annotations.
To export traces, annotate your applications with the `"sidecar.jaegertracing.io/injected": "true"` annotation.

## View traces on the Jaeger UI

You can view the UI by port forwarding the Jaeger query service or by configuring an ingress controller for HTTPS access.
Explore the Jaeger configuration in more detail using the
[Jaeger Custom Resource Documentation](https://www.jaegertracing.io/docs/1.33/operator/#configuring-the-custom-resource).


## Configure the Istio mesh to use Jaeger tracing

Istio mesh traffic can be viewed by enabling Istio's distributed tracing integration. Traces from the Istio mesh provide observability on application traffic
that passes through Istio's ingress and egress gateways.

Istio tracing is disabled by default. To turn on traces, customize your Istio component like the following example.

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
If you want a different sampling rate, configure your desired rate using the `meshConfig.defaultConfig.tracing.sampling` Istio install argument:

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