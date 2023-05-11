---
title: LoggingTrait
description: "A trait supporting the definition of application logging parameters"
weight: 4
draft: false
---
The [LoggingTrait]({{< relref "/docs/reference/vao-oam-v1alpha1#oam.verrazzano.io/v1alpha1.LoggingTrait" >}}) custom resource contains the configuration for an additional logging sidecar with a custom image and Fluentd configuration file.
Here is a sample ApplicationConfiguration that includes a LoggingTrait.
To deploy an example application with this LoggingTrait, replace the ApplicationConfiguration of the [ToDo-List]({{< relref "/docs/examples/wls-coh/todo-list" >}}) example application with the following sample.

{{< clipboard >}}
<div class="highlight">

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
                  loggingImage: fluent/fleuntd-example-image # Replace with custom Fluentd Image
                  loggingConfig: |-
                    # Replace with Fluentd config file
                    <match **>
                    @type stdout
                    </match>
        - componentName: todo-jdbc-configmap
        - componentName: todo-mysql-configmap
        - componentName: todo-mysql-service
        - componentName: todo-mysql-deployment


</div>
{{< /clipboard >}}

In this sample configuration, the LoggingTrait `logging-trait-example` is set on the `todo-domain` application component and defines a logging sidecar with the given Fluentd image and configuration file.
This sidecar will be attached to the component's pod and will gather logs according to the given Fluentd configuration file.
In order for the Fluentd DaemonSet to collect the custom logs, the Fluentd configuration file needs to direct the logs to `STDOUT`, as demonstrated in the previous example.

For example, when the [ToDo-List]({{< relref "/docs/examples/wls-coh/todo-list" >}}) example ApplicationConfiguration is successfully deployed with a LoggingTrait, the `tododomain-adminserver` pod will have a container named `logging-stdout`.
{{< clipboard >}}
<div class="highlight">

    $ kubectl get pods tododomain-adminserver -n todo-list -o jsonpath='{.spec.containers[*].name}'
      ... logging-stdout ...

</div>
{{< /clipboard >}}

In this example, the `logging-stdout` container will run the image given in the LoggingTrait and a ConfigMap named `logging-stdout-todo-domain-domain` will be created with the custom Fluentd configuration file.

