---
title: LoggingScope Custom Resource Definition
linkTitle: LoggingScope Custom Resource Definition
weight: 2
draft: false
---

The LoggingScope custom resource contains the configuration information needed to enable logging for an application component. .  Here is a sample LoggingScope.
```
apiVersion: oam.verrazzano.io/v1alpha1
kind: LoggingScope
metadata:
  name: logging-scope
  namespace: todo-list
spec:
  fluentdImage: ghcr.io/verrazzano/fluentd-kubernetes-daemonset:v1.10.4-20201016214205-7f37ac6
  elasticSearchURL: http://vmi-system-es-ingest.verrazzano-system.svc.cluster.local:9200
  secretName: verrazzano
  workloadRefs: []
```

Here is a sample ApplicationConfiguration that specifies a LoggingScope  (to deploy this application, see the instructions [here](https://github.com/verrazzano/examples/blob/master/todo-list/README.md)).

Note that if an ApplicationConfiguration does not specify a LoggingScope then a default LoggingScope will be generated.
```
apiVersion: core.oam.dev/v1alpha2
kind: ApplicationConfiguration
metadata:
  name: todo-appconf
  namespace: todo-list
  annotations:
    version: v1.0.0
    description: "ToDo List example application"
spec:
  components:
    - componentName: todo-domain
      traits:
        - trait:
            apiVersion: oam.verrazzano.io/v1alpha1
            kind: MetricsTrait
            spec:
              scraper: verrazzano-system/vmi-system-prometheus-0
        - trait:
            apiVersion: oam.verrazzano.io/v1alpha1
            kind: IngressTrait
            spec:
              rules:
                - paths:
                    - path: "/todo"
                      pathType: Prefix
      scopes:
        - scopeRef:
            apiVersion: oam.verrazzano.io/v1alpha1
            kind: LoggingScope
            name: logging-scope
    - componentName: todo-jdbc-configmap
    - componentName: todo-mysql-configmap
    - componentName: todo-mysql-service
    - componentName: todo-mysql-deployment

```
In the above example, the logs for the `todo-domain` component will be written to the ElasticSearch instance specified in the LoggingScope.

With the above application configuration successfully deployed, you can get the log messages for the index `todo-list-todo-appconf-todo-domain`.
```
$ HOST=$(kubectl get ingress -n verrazzano-system vmi-system-es-ingest -o jsonpath={.spec.rules[0].host})
$ VZPASS=$(kubectl get secret --namespace verrazzano-system verrazzano -o jsonpath={.data.password} | base64 --decode; echo)
$ curl -ik --user verrazzano:$VZPASS https://$HOST/todo-list-todo-appconf-todo-domain/_doc/_search?q=message:*

{"took":883,"timed_out":false,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0},"hits":{"total":{"value":235,"relation":"eq"},"max_score":1.0,"hits":[{"_index":"todo-list-todo-appconf-todo-domain","_type":"_doc","_id":"AWV8YXgB5tCoQIDeiWXB","_score":1.0,"_source":{"timestamp":"Mar 23, 2021 11:46:22,784 PM GMT","level":"Info","subSystem":"Security","serverName":"tododomain-adminserver","serverName2":"","threadName":"main","info1":"","info2":"","info3":"","sequenceNumber":"1616543182784","severity":"[severity-value: 64] [partition-id: 0] [partition-name: DOMAIN] ","messageID":"BEA-090905"...
```


#### LoggingScope

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `oam.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | `LoggingScope` |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  Yes |
| `spec` |  [LoggingScopeSpec](#LoggingScopeSpec) | The desired state of a logging scope. |  Yes |

#### LoggingScopeSpec
LoggingScopeSpec specifies the desired state of a logging scope.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `fluentdImage` | string | The fluentd image. | No |
| `elasticSearchURL` | string | The URL for Elasticsearch. | No |
| `secretName` | string | The name of secret with Elasticsearch credentials. | No |
