---
title: "Jaeger Tracing"
linkTitle: Jaeger Tracing
description: "Configure Jaeger to capture application traces"
weight: 1
draft: false
---

Jaeger is a distributed tracing system, used for monitoring and troubleshooting microservices. 
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

Jaeger is installed using the Jaeger Custom Resource Definition. An example is provided below to install Jaeger inside the Istio mesh using the 
Verrazzano system OpenSearch cluster as a tracing backend.

Before creating the Jaeger instance, create a secret that Jaeger will use to load OpenSearch credentials from, using your OpenSearch username and password:

```
kubectl create secret generic jaeger-secret \
  --from-literal=ES_PASSWORD=<OPENSEARCH PASSWORD> \
  --from-literal=ES_USERNAME=<OPENSEARCH USERNAME>
```

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

## Configure an application to export traces to Jaeger

If your application is configured to use tracing libraries, Jaeger can be instructed to export those traces using annotations.
To export traces, annotate your applications with the `"sidecar.jaegertracing.io/injected": <Jaeger Installation Name>` annotation.
This annotation instructs Jaeger to inject an agent sidecar into application pods. Make sure to use your Jaeger instance name
to ensure traces are exported to the correct Jaeger instance.

From the above example, the annotation is `"sidecar.jaegertracing.io/injected": verrazzano-prod`

## View traces on the Jaeger UI

The UI can be viewed by port forwarding the Jaeger query service, or configured to use an ingress controller for HTTPS access.
Jaeger configuration can be explored in more detail using the 
[Jaeger Custom Resource Documentation](https://www.jaegertracing.io/docs/1.33/operator/#configuring-the-custom-resource).
