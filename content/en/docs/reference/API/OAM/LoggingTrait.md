---
title: LoggingTrait Custom Resource Definition
linkTitle: LoggingTrait CRD
weight: 2
draft: false
---
The `LoggingTrait` custom resource contains the configuration for an additional logging sidecar with a custom image and Fluentd configuration file.
Here is a sample `ApplicationConfiguration` that includes a `LoggingTrait`. 
To deploy an example application with this `LoggingTrait`, replace the `ApplicationConfiguration` of the [ToDo-List]({{< relref "/docs/samples/todo-list" >}}) example application with the following sample.

```yaml
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
            kind: LoggingTrait
            metadata:
              name: logging-trait-example
              namespace: todo-list
            spec:
              workloadRef:
                name: "todo-domain"
                apiVersion: oam.verrazzano.io/v1alpha1
                kind: VerrazzanoWebLogicWorkload
              loggingImage: fluent/fleuntd-example-image # Replace with custom Fluentd Image
              loggingConfig:
                fluent.conf: "
                  # Replace with Fluentd config file
                  <match **>
                  @type stdout
                  </match>"
    - componentName: todo-jdbc-configmap
    - componentName: todo-mysql-configmap
    - componentName: todo-mysql-service
    - componentName: todo-mysql-deployment
```
In this sample configuration, the LoggingTrait `logging-trait-example` is set on the `todo-domain` application component and defines a logging sidecar with the given Fluentd image and configuration file.
This sidecar will be attached to the component's pod and will gather logs according to the given Fluentd configuration file. 
In order for the Fluentd DaemonSet to collect the custom logs, the Fluentd configuration file needs to direct the logs to `STDOUT` as demonstrated in the previous example.

For example, when the [ToDo-List]({{< relref "/docs/samples/todo-list" >}}) example `ApplicationConfiguration` is successfully deployed with a `LoggingTrait`, the `tododomain-adminserver` pod will have a container named `logging-stdout`.
```bash
$ kubectl get pods tododomain-adminserver -n todo-list -o jsonpath='{.spec.containers[*].name}'
  ... logging-stdout ...
```
In this example, the `logging-stdout` container will run the image given in the `LoggingTrait` and a ConfigMap named `logging-stdout-todo-domain-domain` will be created with the custom Fluentd configuration file.

#### LoggingTrait

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `oam.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | LoggingTrait | Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. | No |
| `spec` |  [LoggingTraitSpec](#loggingtraitspec) | The desired state of an ingress trait. | Yes |

#### LoggingTraitSpec
`LoggingTraitSpec` specifies the desired state of an ingress trait.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `loggingConfig` | map[string]string | A  of the Fluentd configuration file name and the configuration file details. | Yes |
| `loggingImage` | string | The name of the custom Fluentd image. | Yes |
| `workloadRef` | [WorkloadReference](#workloadReference) | The name of the custom Fluentd image. | Yes |

#### WorkloadReference
`WorkloadReference` specifies the desired workload information.
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | API Version for the desired workload | Yes |
| `kind` | string | Kind of the desired workload | Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. | No |