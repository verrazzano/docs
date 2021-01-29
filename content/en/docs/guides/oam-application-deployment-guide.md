---
title: "Application Deployment Guide"
linkTitle: "Application Deployment"
description: "A guide for deploying an example application on Verrazzano"
weight: 4
draft: false
---


## Overview

Developing and deploying an application to [Verrazzano](https://verrazzano.io/) consists of:
1. Packaging the application as a Docker image.
1. Publishing the application's Docker image to a container registry.
1. Applying the application's Verrazzano Components to the cluster.
1. Applying the application's Verrazzano Applications to the cluster.

This guide does not provide the full details for the first two steps. An existing example application
Docker image has been packaged and published for use.

## What you need

- About 10 minutes.

- Access to an existing Kubernetes cluster with Verrazzano [installed]({{< relref "/quickstart.md#install-verrazzano" >}}).

- Access to the application's image in the Oracle Container Registry.

   Confirm access using this command to pull the example's Docker image.

   ```
   docker pull container-registry.oracle.com/verrazzano/example-hello-world-helidon:0.1.10-3-e5ae893-124
   ```

## Application Development
This guide uses an example application which was written with Java and [Helidon](https://helidon.io).
For the implementation details, see the [Helidon MP tutorial](https://helidon.io/docs/latest/#/mp/guides/10_mp-tutorial).
See the application [source code](https://github.com/verrazzano/examples/tree/master/hello-helidon) in the Verrazzano examples repository.

The example application is a JAX-RS service and implements the following REST endpoints:
- `/greet` - Returns a default greeting message that is stored in memory.
  This endpoint accepts the `GET` HTTP request method.
- `/greet/{name}` - Returns a greeting message including the name provided in the path parameter.
  This endpoint accepts the `GET` HTTP request method.
- `/greet/greeting` - Changes the greeting message to be used in future calls to the other endpoints.
  This endpoint accepts the `PUT` HTTP request method and a JSON payload.

The following code shows a portion of the application's implementation.
The Verrazzano examples repository contains the complete [implementation](https://github.com/verrazzano/examples/blob/master/hello-helidon/helidon-app-greet-v1/src/main/java/io/helidon/examples/quickstart/mp/GreetResource.java).
An important detail here is that the application contains a single resource exposed on path `/greet`.

```java
package io.helidon.examples.quickstart.mp;
...
@Path("/greet")
@RequestScoped
public class GreetResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public JsonObject getDefaultMessage() {
        ...
    }

    @Path("/{name}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public JsonObject getMessage(@PathParam("name") String name) {
        ...
    }

    @Path("/greeting")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    ...
    public Response updateGreeting(JsonObject jsonObject) {
        ...
    }

}
```

A Dockerfile is used to package the completed application JAR file into a Docker image.
The following code shows a portion of the Dockerfile.
The Verrazzano examples repository contains the complete [Dockerfile](https://github.com/verrazzano/examples/blob/master/hello-helidon/helidon-app-greet-v1/Dockerfile).
Note that the Docker container exposes a single port 8080.

```dockerfile
FROM container-registry.oracle.com/os/oraclelinux:7-slim@sha256:9b86d1332a883ee8f68dd44ba42133de518b2e0ec1cc70257e59fb4da86b1ad3
...
CMD java -cp /app/helidon-quickstart-mp.jar:/app/* io.helidon.examples.quickstart.mp.Main
EXPOSE 8080
```

## Application Deployment

When you deploy applications with Verrazzano, the platform sets up connections, network policies, and
ingresses in the service mesh, and wires up a monitoring stack to capture the metrics, logs, and traces.
Verrazzano employs Open Application Model [OAM] Components to define the functional units of a system that are then
assembled together and configured by defining OAM Application Configurations.

### Verrazzano OAM Component

A Verrazzano OAM Component is a
[Kubernetes Custom Resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
describing an application's general composition and environment requirements.
The following code shows the component for the example application used in this guide.
This model describes a component which is implemented by a single Docker image containing a Helidon application exposing a single endpoint.
For more details about Verrazzano Components, see TBD documentation.

```yaml
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: hello-helidon-component
  namespace: hello-helidon
spec:
  workload:
    apiVersion: core.oam.dev/v1alpha2
    kind: ContainerizedWorkload
    metadata:
      name: hello-helidon-workload
      namespace: hello-helidon
      labels:
        app: hello-helidon
    spec:
      containers:
      - name: hello-helidon-container
        image: "ghcr.io/verrazzano/example-helidon-greet-app-v1:0.1.10-3-20201016220428-56fb4d4"
        ports:
          - containerPort: 8080
            name: http
```

A brief description of each field in the model:

* `apiVersion` - Version of the model custom resource definition
* `kind` - Standard name of the model custom resource definition
* `metadata.name` - The name used to create the model's custom resource
* `metadata.namespace` - The namespace used to create this model's custom resource
* `spec.workload.kind` - `ContainerizedWorkload` defines a stateless workload of Kubernetes
* `spec.workload.spec.containers` - The implementation containers
* `spec.workload.spec.containers.ports` - Ports exposed by the container

### Verrazzano Application Configurations

A Verrazzano Application Configuration is a
[Kubernetes Custom Resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
which provides environment specific customizations.
The following code shows the application configuration for the example used in this guide.
This resource specifies the deployment of the application to the `hello-helidon` namespace.  Additional runtime features are 
specified using traits, or runtime overlays that augment the workload.  For example, the ingress trait specifies the 
ingress host and path, while the metrics trait provides the runtime with the Prometheus scraper leveraged to obtain the 
application related metrics.
For more details about Verrazzano application configurations, see TBD documentation.

```yaml
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
                - hosts:
                    - "hello-helidon.example.com"
                  paths:
                    - path: "/greet"
                      pathType: Prefix
```

A brief description of each field in the binding:

* `apiVersion` - Version of the ApplicationConfiguration custom resource definition
* `kind` - Standard name of the application configuration custom resource definition
* `metadata.name` - The name used to create this application configuration resource
* `metadata.namespace` - The namespace used for this application configuration custom resource
* `spec.components` - Reference to the application's components leveraged to specify runtime configuration
* `spec.components[].traits` - The traits specified for the application's components

To explore traits we can examine the fields of an ingress trait:

* `apiVersion` - Version of the OAM trait custom resource definition
* `kind` - `IngressTrait` is the name of the OAM application ingress trait custom resource definition
* `spec.rules.hosts` - The hosts specified for the ingress
* `spec.rules.paths` - The context paths for accessing the application

### Deploy the application

The following steps are required to deploy the example application.
Steps similar to the `apply` steps would be used to deploy any application to Verrazzano.

1. Clone the Verrazzano [repository](https://github.com/verrazzano/verrazzano).

   ```shell script
   git clone https://github.com/verrazzano/verrazzano.git
   ```

1. Change the current directory to the example `hello-helidon` directory.

   ```shell script
   cd verrazzano/examples/hello-helidon
   ```
   {{< alert title="NOTE" color="tip" >}}
   The remainder of this guide uses file locations relative to this directory.
   {{< /alert >}}

1. Apply the application's component.

   ```shell script
   kubectl apply -f ./hello-helidon-comp.yaml
   ```

   This step causes the validation and creation of the component resource.
   No other resources or objects are created as a result.
   Application configurations applied in the future may reference this component model.

1. Apply the application configuration.

   ```shell script
   kubectl apply -f ./hello-helidon-app.yaml
   ```

   This step causes the validation and creation of the application configuration resource.
   This operation triggers the activation of a number of Verrazzano operators.
   These operators create other Kubernetes objects (for example, Deployments, ReplicaSets, Pods, Services, Ingresses)
   that collectively provide and support the application.

1. Configure the application's DNS resolution.

   After deploying the application, configure DNS to resolve the application's
   ingress DNS name to the application's load balancer IP address.
   The application's DNS host name is the value of the host specified in the application configuration's
   ingress trait (see the `spec.rules.hosts` value provided in the application configuration's ingress trait).
   The load balancer IP is obtained by querying Kubernetes for the
   Istio ingress gateway status:

   ```shell script
   kubectl get service -n istio-system istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}
   ```

   DNS configuration steps are outside the scope of this guide. For DNS infrastructure that can be configured and used, see
   the [Oracle Cloud Infrastructure DNS](https://docs.cloud.oracle.com/en-us/iaas/Content/DNS/Concepts/gettingstarted.htm) documentation.
   In some small non-production scenarios, DNS configuration using
   `/etc/hosts` or an equivalent may be sufficient.

### Verify the deployment

  Applying the application configuration initiates the creation of several Kubernetes objects.
  Actual creation and initialization of these objects occurs asynchronously.
  The following steps provide commands for determining when these objects are ready for use.

  **Note**: Many other Kubernetes objects unrelated to the example application may also exist.
  Those have been omitted from the lists.

1. Verify the Helidon application pod is running.

   ```
   $ kubectl get pods -n hello-helidon | grep '^NAME\|hello-helidon-workload'

   NAME                                     READY   STATUS    RESTARTS   AGE
   hello-helidon-workload-9dfbbfb74-4jm9v   1/1     Running   0          94m
   ```

   The parameter `hello-helidon-workload` is from the component's
   `spec.workload.metadata.name` value.

1. Verify the Verrazzano application operator pod is running.

   ```
   $ kubectl get pods -n verrazzano-system | grep '^NAME\|verrazzano-application-operator'

   NAME                                                     READY   STATUS    RESTARTS   AGE
   verrazzano-application-operator-5485967588-lp6cw         1/1     Running   0          8d
   ```

   The namespace `verrazzano-system` is used by Verrazzano for
   non-application objects managed by Verrazzano.
   A single `verrazzano-application-operator` manages the life cycle of
   all OAM based applications within the cluster.

1. Verify the Verrazzano monitoring infrastructure is running.

   ```
   $ kubectl get pods -n verrazzano-system | grep '^NAME\|vmi-system'

   NAME                                                     READY   STATUS    RESTARTS   AGE
   vmi-system-api-6fb4fd57cb-95ttz                          1/1     Running   0          8d
   vmi-system-es-master-0                                   1/1     Running   0          11h
   vmi-system-grafana-674b4f5df7-f4f2p                      1/1     Running   0          8d
   vmi-system-kibana-759b854fc6-4tsjv                       1/1     Running   0          8d
   vmi-system-prometheus-0-f6f587664-pfm54                  3/3     Running   0          101m
   vmi-system-prometheus-gw-68c45f84b8-jrxlt                1/1     Running   0          8d
   ```

   These pods in the `verrazzano-system` namespace constitute a
   monitoring stack created by Verrazzano for the deployed applications.

   The monitoring infrastructure comprises several components:
   * `vmi-system-api` - Internal API for configuring monitoring
   * `vmi-system-es` - Elasticsearch for log collection
   * `vmi-system-kibana` - Kibana for log visualization
   * `vmi-system-grafana` - Grafana for metric visualization
   * `vmi-system-prometheus` - Prometheus for metric collection
   <p/>

1. Verify the Verrazzano metrics collection infrastructure is running.

   ```
   $ kubectl get pods -n monitoring | grep '^NAME\|prom-pusher-system'

   NAME                                  READY   STATUS    RESTARTS   AGE
   prom-pusher-system-65744b658f-tpkqj   1/1     Running   0          8d
   ```

   This pod in the `monitoring` namespace is also part of the applications
   monitoring stack provided by Verrazzano.
   This process pushes collected metrics to Prometheus.

1. Diagnose failures.

   View the event logs of any pod not entering the `Running` state within
   a reasonable length of time, such as five minutes.

   ```shell script
   kubectl describe pod -n hello-helidon hello-helidon-workload-9dfbbfb74-4jm9v
   ```

   Use the specific namespace and name for the pod being investigated.

### Explore the application

Follow these steps to explore the application's functionality.
If DNS was not configured, then use the alternative commands.

1.  Save the host name and IP address of the load balancer exposing the application's REST service endpoints for later.
    ```shell script
    HOST='hello-helidon.example.com'
    ADDRESS=$(kubectl get service -n istio-system istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    ```
    **NOTE**:

    * The value of `ADDRESS` is used only if DNS has not been
    configured.
    * The following alternative commands may not work in conjunction
    with firewalls that validate `HTTP Host` headers.


1.  Get the default message.
    ```shell script
    $ curl -s -X GET "http://${HOST}/greet"

    {"message":"Hello World!"}
    ```
    If DNS has not been configured, then use this command.
    ```shell script
    $ curl -s -X GET "http://${ADDRESS}/greet" -H "Host: ${HOST}"
    ```

1.  Get a message for Robert.
    ```shell script
    $ curl -s -X GET "http://${HOST}/greet/Robert"

    {"message":"Hello Robert!"}
    ```
    If DNS has not been configured, then use this command.
    ```shell script
    $ curl -s -X GET "http://${ADDRESS}/greet/Robert" -H "Host: ${HOST}"
    ```

1.  Update the default greeting.
    ```shell script
    $ curl -s -X PUT "http://${HOST}/greet/greeting" -H 'Content-Type: application/json' -d '{"greeting" : "Greetings"}'
    ```
    If DNS has not been configured, then use this command.
    ```shell script
    $ curl -s -X PUT "http://${ADDRESS}/greet/greeting" -H 'Content-Type: application/json' -d '{"greeting" : "Greetings"}' -H "Host: ${HOST}"
    ```

1.  Get the new message for Robert.
    ```shell script
    $ curl -s -X GET "http://${HOST}/greet/Robert"

    {"message":"Welcome Robert!"}
    ```
    If DNS has not been configured, then use this command.
    ```shell script
    $ curl -s -X GET "http://${ADDRESS}/greet/Robert" -H "Host: ${HOST}"
    ```

### Access the application's logs

Deployed applications have log collection enabled.
These logs are collected using Elasticsearch and can be accessed using Kibana.
Elasticsearch and Kibana are examples of infrastructure Verrazzano creates in support of an application as a result of applying an application configuration.

Determine the URL to access Kibana using the following commands.
 ```shell script
KIBANA_HOST=$(kubectl get ingress -n verrazzano-system vmi-hello-world-binding-kibana -o jsonpath='{.spec.rules[0].host}')
KIBANA_URL="https://${KIBANA_HOST}"
echo "${KIBANA_URL}"
open "${KIBANA_URL}"
```

The user name to access Kibana defaults to `verrazzano` during the Verrazzano installation.

Determine the password to access Kibana using the following command:
```shell script
echo $(kubectl get secret -n verrazzano-system verrazzano -o jsonpath={.data.password} | base64 --decode)
```

### Access the application's metrics

Deployed applications have metric collection enabled.
Grafana can be used to access these metrics collected by Prometheus.
Prometheus and Grafana are additional components Verrazzano creates as a result of applying an application configuration.

Determine the URL to access Grafana using the following commands.

```shell script
GRAFANA_HOST=$(kubectl get ingress -n verrazzano-system vmi-system-grafana -o jsonpath='{.spec.rules[0].host}')
GRAFANA_URL="https://${GRAFANA_HOST}"
echo "${GRAFANA_URL}"
open "${GRAFANA_URL}"
```
The user name to access Grafana is set to the default value `verrazzano` during the Verrazzano installation.

Determine the password to access Grafana using the following command.

```shell script
echo $(kubectl get secret -n verrazzano-system verrazzano -o jsonpath={.data.password} | base64 --decode)
```

Alternatively, metrics can be accessed directly using Prometheus.
Determine the URL for this access using the following commands.

```shell script
PROMETHEUS_HOST=$(kubectl get ingress -n verrazzano-system vmi-system-prometheus -o jsonpath='{.spec.rules[0].host}')
PROMETHEUS_URL="https://${PROMETHEUS_HOST}"
echo "${PROMETHEUS_URL}"
open "${PROMETHEUS_URL}"
```

The user name and password for both Prometheus and Grafana are the same.

## Application Removal

Run the following commands to delete the application configuration and, optionally, component.

1. Delete the application configuration.

   ```shell script
   kubectl delete -f ./hello-helidon-app.yaml
   ```

   The deletion of the application configuration will result in the destruction
   of all application-specific Kubernetes objects.

1. (Optional) Delete the application's component.

   ```shell script
   kubectl delete -f ./hello-helidon-comp.yaml
   ```
   **Note**: This step is not required if other application configurations for this component will be applied in the future.
