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
1. Applying the application's Verrazzano Application Model to the cluster.
1. Applying the application's Verrazzano Application Binding to the cluster.

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
Verrazzano employs an "application model" that lets you assemble applications into a system that can be
managed together and an "application binding" that you use to map the application model to an environment.

### Verrazzano Application Model

A Verrazzano Application Model is a
[Kubernetes Custom Resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
describing an application's general composition and environment requirements.
The following code shows the model for the example application used in this guide.
This model describes an application which is implemented by a single Docker image containing a Helidon application exposing a single endpoint.
For more details about Verrazzano models, see the [Verrazzano Application Model](https://verrazzano.io/docs/reference/model/) documentation.

```yaml
apiVersion: verrazzano.io/v1beta1
kind: VerrazzanoModel
metadata:
  name: hello-world-model
  namespace: default
spec:
  description: "Hello World application"
  helidonApplications:
    - name: "hello-world-application"
      image: "container-registry.oracle.com/verrazzano/example-hello-world-helidon:0.1.10-3-e5ae893-124"
      connections:
        - ingress:
            - name: "greet-ingress"
              match:
                - uri:
                    prefix: "/greet"
```

A brief description of each field in the model:

* `apiVersion` - Version of the model custom resource definition
* `kind` - Standard name of the model custom resource definition
* `metadata.name` - The name used to create the model's custom resource
* `metadata.namespace` - The namespace used to create this model's custom resource
* `spec.helidonApplications.name` - Name used to identify this application from the binding
* `spec.helidonApplications.image` - Docker image used to implement the application
* `spec.helidonApplications.connections.ingress.name` - Name used to identify this ingress from the binding
* `spec.helidonApplications.connections.ingress.match.uri.prefix` - URI prefix for the application's ingress

### Verrazzano Application Binding

A Verrazzano Application Binding is a
[Kubernetes Custom Resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
which provides environment specific customizations.
The following code shows the binding for the example application used in this guide.
This binding specifies that the application be placed in the `local` cluster
within the `greet` namespace having an ingress endpoint bound to DNS name `www.example.com`.
For more details about Verrazzano bindings, see the [Verrazzano
Application Binding](https://verrazzano.io/docs/reference/binding/) documentation.

```yaml
apiVersion: verrazzano.io/v1beta1
kind: VerrazzanoBinding
metadata:
  name: hello-world-binding
  namespace: default
spec:
  description: "Hello World Application binding"
  modelName: hello-world-model
  placement:
    - name: local
      namespaces:
        - name: greet
          components:
            - name: hello-world-application
  ingressBindings:
    - name: "greet-ingress"
      dnsName: "www.example.com"
```

A brief description of each field in the binding:

* `apiVersion` - Version of the Verrazzano binding custom resource definition
* `kind` - Standard name of the Verrazzano binding custom resource definition
* `metadata.name` - The name used to create this binding's custom resource
* `metadata.namespace` - The namespace used to create this binding's custom resource
* `spec.modelName` - Reference to the application's model custom resource
* `spec.placement.name` - Name of the Kubernetes cluster into which the application will be deployed
* `spec.placement.namespaces.name` - Name of a namespace in which to place the application's deployed components
* `spec.placement.namespaces.components.name` - Name of a model's component to deploy within the namespace
* `spec.ingressBindings.name` - Reference to a model's ingress
* `spec.ingressBindings.dnsName` - The DNS name to use for the ingress when created

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

1. Apply the application's model.

   ```shell script
   kubectl apply -f ./hello-world-model.yaml
   ```

   This step causes the validation and creation of the model resource.
   No other resources or objects are created as a result.
   Bindings applied in the future may reference this model.

1. Apply the application's binding.

   ```shell script
   kubectl apply -f ./hello-world-binding.yaml
   ```

   This step causes the validation and creation of the binding resource.
   The binding creation triggers the activation of a number of Verrazzano operators.
   These operators create other Kubernetes objects (for example, Deployments, ReplicaSets, Pods, Services, Ingresses)
   that collectively provide and support the application.

1. Configure the application's DNS resolution.

   After deploying the application, configure DNS to resolve the application's
   ingress DNS name to the application's load balancer IP address.
   The application's DNS name is the value of the binding's
   `spec.ingressBindings.dnsName` field.
   The load balancer IP is obtained by querying Kubernetes for the
   Istio ingress gateway status.

   ```shell script
   kubectl get service -n istio-system istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}
   ```

   DNS configuration steps are outside the scope of this guide. For DNS infrastructure that can be configured and used, see
   the [Oracle Cloud Infrastructure DNS](https://docs.cloud.oracle.com/en-us/iaas/Content/DNS/Concepts/gettingstarted.htm) documentation.
   In some small non-production scenarios, DNS configuration using
   `/etc/hosts` or an equivalent may be sufficient.

### Verify the deployment

  Applying the binding initiates the creation of several Kubernetes objects.
  Actual creation and initialization of these objects occurs asynchronously.
  The following steps provide commands for determining when these objects are ready for use.

  **Note**: Many other Kubernetes objects unrelated to the example application may also exist.
  Those have been omitted from the lists.

1. Verify the Helidon application pod is running.

   ```
   $ kubectl get pods -n greet | grep '^NAME\|hello-world-application'

   NAME                                       READY   STATUS    RESTARTS   AGE
   hello-world-application-648f8f79d9-8xkhl   3/3     Running   0          2h
   ```

   The parameter `greet` is from the model's
   `spec.placement.namespaces.name` value.
   The parameter `hello-world-application` is from the model's
   `spec.placement.namespaces.components.name` value.

1. Verify the Verrazzano Helidon application operator pod is running.

   ```
   $ kubectl get pods -n verrazzano-system | grep '^NAME\|verrazzano-helidon-app-operator'

   NAME                                                     READY   STATUS    RESTARTS   AGE
   verrazzano-helidon-app-operator-d746d7bc6-67th8          1/1     Running   0          2h
   ```

   The namespace `verrazzano-system` is used by Verrazzano for
   non-application objects managed by Verrazzano.
   A single `verrazzano-helidon-app-operator` manages the life cycle of
   all Helidon-based applications within the cluster.

1. Verify the Verrazzano monitoring infrastructure is running.

   ```
   $ kubectl get pods -n verrazzano-system | grep '^NAME\|vmi-hello-world-binding'

   NAME                                                     READY   STATUS    RESTARTS   AGE
   vmi-hello-world-binding-api-69987d6dbb-stpd4             1/1     Running   0          2h
   vmi-hello-world-binding-es-data-0-55b679d6bb-5g2bf       2/2     Running   0          2h
   vmi-hello-world-binding-es-data-1-7888dbdfcf-76ff9       2/2     Running   0          2h
   vmi-hello-world-binding-es-ingest-b7d59fb69-6hbr4        1/1     Running   0          2h
   vmi-hello-world-binding-es-master-0                      1/1     Running   0          2h
   vmi-hello-world-binding-es-master-1                      1/1     Running   0          2h
   vmi-hello-world-binding-es-master-2                      1/1     Running   0          2h
   vmi-hello-world-binding-grafana-85b669cdbc-4rszf         1/1     Running   0          2h
   vmi-hello-world-binding-kibana-64f958c7f-knxk4           1/1     Running   0          2h
   vmi-hello-world-binding-prometheus-0-598f79557-ttzmz     3/3     Running   0          2h
   vmi-hello-world-binding-prometheus-gw-6df8bf4689-dmfxh   1/1     Running   0          2h
   ```

   These pods in the `verrazzano-system` namespace constitute a
   monitoring stack created by Verrazzano for each binding.
   The `hello-world-binding` portion of the pod names are from the
   binding's `metadata.name` value.

   The monitoring infrastructure comprises several components:
   * `vmi-hello-world-binding-api` - Internal API for configuring monitoring
   * `vmi-hello-world-binding-es` - Elasticsearch for log collection
   * `vmi-hello-world-binding-kibana` - Kibana for log visualization
   * `vmi-hello-world-binding-grafana` - Grafana for metric visualization
   * `vmi-hello-world-binding-prometheus` - Prometheus for metric collection
   <p/>

1. Verify the Verrazzano metrics collection infrastructure is running.

   ```
   $ kubectl get pods -n monitoring | grep '^NAME\|prom-pusher-hello-world-binding'

   NAME                                               READY   STATUS    RESTARTS   AGE
   prom-pusher-hello-world-binding-6648484f89-t8rf8   1/1     Running   0          2h  
   ```

   These pods in the `monitoring` namespace are also part of the
   monitoring stack created by Verrazzano for each binding.
   The `hello-world-binding` portion of the pod names are from the
   binding's `metadata.name` value.
   These components push collected metrics to Prometheus.

1. Diagnose failures.

   View the event logs of any pod not entering the `Running` state within
   a reasonable length of time, such as five minutes.

   ```shell script
   kubectl describe pod -n greet hello-world-application-648f8f79d9-8xkhl
   ```

   Use the specific namespace and name for the pod being investigated.

### Explore the application

Follow these steps to explore the application's functionality.
If DNS was not configured, then use the alternative commands.

1.  Save the host name and IP address of the load balancer exposing the application's REST service endpoints for later.
    ```shell script
    HOST='www.example.com'
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

Applications deployed using bindings have log collection enabled.
These logs are collected using Elasticsearch and can be accessed using Kibana.
Elasticsearch and Kibana are examples of infrastructure Verrazzano creates in support of an application as a result of applying a binding.

Determine the URL to access Kibana using the following commands.
 ```shell script
KIBANA_HOST=$(kubectl get ingress -n verrazzano-system vmi-hello-world-binding-kibana -o jsonpath='{.spec.rules[0].host}')
KIBANA_URL="https://${KIBANA_HOST}"
echo "${KIBANA_URL}"
open "${KIBANA_URL}"
```

The user name to access Kibana defaults to `verrazzano` during the Verrazzano installation.

Determine the password to access Kibana using the following command.
```shell script
echo $(kubectl get secret -n verrazzano-system verrazzano -o jsonpath={.data.password} | base64 --decode)
```

### Access the application's metrics

Applications deployed using bindings have metric collection enabled.
Grafana can be used to access these metrics collected by Prometheus.
Prometheus and Grafana are additional components Verrazzano creates as a result of applying an application binding.

Determine the URL to access Grafana using the following commands.

```shell script
GRAFANA_HOST=$(kubectl get ingress -n verrazzano-system vmi-hello-world-binding-grafana -o jsonpath='{.spec.rules[0].host}')
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
PROMETHEUS_HOST=$(kubectl get ingress -n verrazzano-system vmi-hello-world-binding-prometheus -o jsonpath='{.spec.rules[0].host}')
PROMETHEUS_URL="https://${PROMETHEUS_HOST}"
echo "${PROMETHEUS_URL}"
open "${PROMETHEUS_URL}"
```

The user name and password for Prometheus access are the same as for Grafana.

## Application Removal

Run the following commands to delete the application's binding and, optionally, model.

1. Delete the application's binding.

   ```shell script
   kubectl delete -f ./hello-world-binding.yaml
   ```

   The deletion of the application's binding will result in the destruction
   of all application-specific Kubernetes objects.
   This includes objects created by Verrazzano on behalf of the application,
   such as monitoring components.

1. (Optional) Delete the application's model.

   ```shell script
   kubectl delete -f ./hello-world-model.yaml
   ```
   **Note**: This step is not required if other bindings for this model will be applied in the future.
