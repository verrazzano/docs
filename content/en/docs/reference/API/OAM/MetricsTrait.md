---
title: MetricsTrait Custom Resource Definition
linkTitle: MetricsTrait CRD
weight: 2
draft: false
---
The MetricsTrait custom resource contains the configuration information needed to enable metrics for an application component.  Component workloads configured with a MetricsTrait are setup to emit metrics through an endpoint that are scraped by a given Prometheus deployment.  Here is a sample ApplicationConfiguration that specifies a MetricsTrait.  To deploy an example application that demonstrates a MetricsTrait, see [Hello World Helidon]({{< relref "/docs/samples/hello-helidon/" >}}).

Note that if an ApplicationConfiguration does not specify a MetricsTrait, then a default MetricsTrait will be generated with values appropriate for the workload type.
```
apiVersion: core.oam.dev/v1alpha2
kind: ApplicationConfiguration
metadata:
  name: hello-helidon-appconf
  namespace: hello-helidon
  annotations:
    version: v1.0.0
    description: "Hello Helidon application"
spec:
  components:
    - componentName: hello-helidon-component
      traits:
        - trait:
            apiVersion: oam.verrazzano.io/v1alpha1
            kind: MetricsTrait
            spec:
                scraper: verrazzano-system/vmi-system-prometheus-0
        - trait:
            apiVersion: oam.verrazzano.io/v1alpha1
            kind: IngressTrait
            metadata:
              name: hello-helidon-ingress
            spec:
              rules:
                - paths:
                    - path: "/greet"
                      pathType: Prefix
```
In the sample configuration, a MetricsTrait is specified for the `hello-helidon-component` application component.

With the sample application configuration successfully deployed, you can query for metrics from the application component.
```
$ HOST=$(kubectl get ingress \
     -n verrazzano-system vmi-system-prometheus \
     -o jsonpath={.spec.rules[0].host})
$ echo $HOST

prometheus.vmi.system.default.<ip>.nip.io

$ VZPASS=$(kubectl get secret \
     --namespace verrazzano-system verrazzano \
     -o jsonpath={.data.password} | base64 \
     --decode; echo)
$ curl -sk \
    --user verrazzano:${VZPASS} \
    -X GET https://${HOST}/api/v1/query?query=vendor_requests_count_total

{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"vendor_requests_count_total","app":"hello-helidon","app_oam_dev_component":"hello-helidon-component","app_oam_dev_name":"hello-helidon-appconf","app_oam_dev_resourceType":"WORKLOAD","app_oam_dev_revision":"hello-helidon-component-v1","containerizedworkload_oam_crossplane_io":"496df78f-ef8b-4753-97fd-d9218d2f38f1","job":"hello-helidon-appconf_default_helidon-logging_hello-helidon-component","namespace":"helidon-logging","pod_name":"hello-helidon-workload-b7d9d95d8-ht7gb","pod_template_hash":"b7d9d95d8"},"value":[1616535232.487,"4800"]}]}}
```

#### MetricsTrait

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `oam.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | MetricsTrait |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `spec` |  [MetricsTraitSpec](#metricstraitspec) | The desired state of a metrics trait. |  Yes |

#### MetricsTraitSpec
MetricsTraitSpec specifies the desired state of a metrics trait.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `port` | integer | The HTTP port for the related metrics endpoint. Defaults to 8080. | No |
| `path` | string | The HTTP path for the related metrics endpoint. Defaults to `/metrics`. | No |
| `secret` | string | The name of an opaque secret (for example, user name and password) within the workload’s namespace for metrics endpoint access. | No |
| `scraper` | string | The Prometheus deployment used to scrape the related metrics endpoints. Defaults to `verrazzano-system/vmi-system-prometheus-0`. | No |
