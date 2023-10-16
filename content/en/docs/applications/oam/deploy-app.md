---
title: "Develop and Deploy Applications Using OAM"
description: ""
weight: 3
draft: false
aliases:
  - /docs/guides/app-deployment/application-deployment-guide
---

## Prerequisites
- Access to an existing Kubernetes cluster with Verrazzano [installed]({{< relref "/quickstart.md#install-verrazzano" >}}).
- Access to the application's image in GitHub Container Registry.
<br>  Confirm access using this command to pull the example's Docker image:
{{< clipboard >}}
<div class="highlight">

   ```
   $ docker pull ghcr.io/verrazzano/example-helidon-greet-app-v1:0.1.12-1-20210218160249-d8db8f3
   ```

</div>
{{< /clipboard >}}

## Application development
This section uses an example application which was written with Java and [Helidon](https://helidon.io).
For the implementation details, see the [Helidon MP tutorial](https://helidon.io/docs/latest/#/mp/guides/10_mp-tutorial).
See the application [source code](https://github.com/verrazzano/examples) in the Verrazzano examples repository.

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

{{< clipboard >}}

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
{{< /clipboard >}}

A Dockerfile is used to package the completed application JAR file into a Docker image.
The following code shows a portion of the Dockerfile.
The Verrazzano examples repository contains the complete [Dockerfile](https://github.com/verrazzano/examples/blob/master/hello-helidon/helidon-app-greet-v1/Dockerfile).
Note that the Docker container exposes a single port 8080.

{{< clipboard >}}

```dockerfile
FROM ghcr.io/oracle/oraclelinux:7-slim
...
CMD java -cp /app/helidon-quickstart-mp.jar:/app/* io.helidon.examples.quickstart.mp.Main
EXPOSE 8080
```
{{< /clipboard >}}

## Application deployment

When you deploy applications with Verrazzano, the platform sets up connections, network policies, and
ingresses in the service mesh, and wires up a monitoring stack to capture the metrics, logs, and traces.
Verrazzano employs OAM Components to define the functional units of a system that are then
assembled and configured by defining associated application configurations.

### Verrazzano components

A Verrazzano OAM Component is a
[Kubernetes Custom Resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
describing an application's general composition and environment requirements.
The following code shows the component for the example application used in this guide.
This resource describes a component which is implemented by a single Docker image containing a Helidon application exposing a single endpoint.

{{< clipboard >}}

```yaml
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: hello-helidon-component
  namespace: hello-helidon
spec:
  workload:
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: VerrazzanoHelidonWorkload
    metadata:
      name: hello-helidon-workload
      labels:
        app: hello-helidon
    spec:
      deploymentTemplate:
        metadata:
          name: hello-helidon-deployment
        podSpec:
          containers:
            - name: hello-helidon-container
              image: "ghcr.io/verrazzano/example-helidon-greet-app-v1:0.1.10-3-20201016220428-56fb4d4"
              ports:
                - containerPort: 8080
                  name: http

```
{{< /clipboard >}}

A brief description of each field of the component:

* `apiVersion` - Version of the component custom resource definition
* `kind` - Standard name of the component custom resource definition
* `metadata.name` - The name used to create the component's custom resource
* `metadata.namespace` - The namespace used to create this component's custom resource
* `spec.workload.kind` - `VerrazzanoHelidonWorkload` defines a stateless workload of Kubernetes
* `spec.workload.spec.deploymentTemplate.podSpec.metadata.name` -  The name used to create the stateless workload of Kubernetes  
* `spec.workload.spec.deploymentTemplate.podSpec.containers` - The implementation containers
* `spec.workload.spec.deploymentTemplate.podSpec.containers.ports` - Ports exposed by the container

### Verrazzano application configurations

A Verrazzano application configuration is a
[Kubernetes Custom Resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
which provides environment specific customizations.
The following code shows the application configuration for the example used in this guide.
This resource specifies the deployment of the application to the `hello-helidon` namespace.  Additional runtime features are
specified using traits, or runtime overlays that augment the workload.  For example, the ingress trait specifies the
ingress host and path, while the metrics trait optionally provides the Prometheus scraper used to obtain the
application related metrics.  If no metrics trait is specified, the Verrazzano-supplied Prometheus component is used by default.
{{< clipboard >}}

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
              scraper: <optionally specify custom scraper>
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
{{< /clipboard >}}

A brief description of each field in the application configuration:

* `apiVersion` - Version of the `ApplicationConfiguration` custom resource definition
* `kind` - Standard name of the application configuration custom resource definition
* `metadata.name` - The name used to create this application configuration resource
* `metadata.namespace` - The namespace used for this application configuration custom resource
* `spec.components` - Reference to the application's components leveraged to specify runtime configuration
* `spec.components[].traits` - The traits specified for the application's components

To explore traits, we can examine the fields of an ingress trait:

* `apiVersion` - Version of the OAM trait custom resource definition
* `kind` - `IngressTrait` is the name of the OAM application ingress trait custom resource definition
* `spec.rules.paths` - The context paths for accessing the application

### Deploy the application

The following steps are required to deploy the example application.
Steps similar to the `apply` steps would be used to deploy any application to Verrazzano.

1. Create a namespace for the example application and add labels identifying the namespace as managed by Verrazzano
and enabled for Istio.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl create namespace hello-helidon
   $ kubectl label namespace hello-helidon verrazzano-managed=true istio-injection=enabled
   ```

</div>
{{< /clipboard >}}


1. Apply the application's component.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl apply -f {{< release_source_url raw=true path="examples/hello-helidon/hello-helidon-comp.yaml" >}} -n hello-helidon
   ```

</div>
{{< /clipboard >}}

   This step causes the validation and creation of the Component resource.
   No other resources or objects are created as a result.
   Application configurations applied in the future may reference this Component resource.

1. Apply the application configuration.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl apply -f {{< release_source_url raw=true path="examples/hello-helidon/hello-helidon-app.yaml" >}} -n hello-helidon
   ```

</div>
{{< /clipboard >}}

   This step causes the validation and creation of the application configuration resource.
   This operation triggers the activation of a number of Verrazzano operators.
   These operators create other Kubernetes objects (for example, Deployments, ReplicaSets, Pods, Services, Ingresses)
   that collectively provide and support the application.

1. Configure the application's DNS resolution.

   After deploying the application, configure DNS to resolve the application's
   ingress DNS name to the application's load balancer IP address.
   The generated host name is obtained by querying Kubernetes for the gateway:
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl get gateways.networking.istio.io hello-helidon-hello-helidon-gw \
       -n hello-helidon \
       -o jsonpath='{.spec.servers[0].hosts[0]}'
   ```

</div>
{{< /clipboard >}}

   The load balancer IP is obtained by querying Kubernetes for the
   Istio ingress gateway status:
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl get service \
       -n istio-system istio-ingressgateway \
       -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
   ```

</div>
{{< /clipboard >}}

   DNS configuration steps are outside the scope of this guide. For DNS infrastructure that can be configured and used, see
   the [Oracle Cloud Infrastructure DNS](https://docs.cloud.oracle.com/en-us/iaas/Content/DNS/Concepts/gettingstarted.htm) documentation.
   In some small non-production scenarios, DNS configuration using
   `/etc/hosts` or an equivalent may be sufficient.

### Verify the deployment

  Applying the application configuration initiates the creation of several Kubernetes objects.
  Actual creation and initialization of these objects occurs asynchronously.
  The following steps provide commands for determining when these objects are ready for use.

  **NOTE**: Many other Kubernetes objects unrelated to the example application may also exist.
  Those have been omitted from the lists.

1. Verify the Helidon application pod is running.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl get pods -n hello-helidon -l app=hello-helidon

   # Sample output
   NAME                                        READY   STATUS    RESTARTS   AGE
   hello-helidon-deployment-8664954995-wcb9d   2/2     Running   0          5m5s
   ```

</div>
{{< /clipboard >}}

1. Verify that the Verrazzano application operator pod is running.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl get pod -n verrazzano-system -l app=verrazzano-application-operator

   # Sample output
   NAME                                               READY   STATUS    RESTARTS   AGE
   verrazzano-application-operator-79849b89ff-lr9w6   1/1     Running   0          13m
   ```

</div>
{{< /clipboard >}}

   The namespace `verrazzano-system` is used by Verrazzano for
   non-application objects managed by Verrazzano.
   A single `verrazzano-application-operator` manages the life cycle of
   all OAM based applications within the cluster.

1. Verify the Verrazzano logging and monitoring infrastructure is running.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl get pods -n verrazzano-system | grep '^NAME\|vmi-system'

   # Sample output
   NAME                                               READY   STATUS    RESTARTS   AGE
   vmi-system-grafana-799d79648d-wsdp4                2/2     Running   0          47m
   vmi-system-kiali-574c6dd94d-f49jv                  2/2     Running   0          51m
   ```

</div>
{{< /clipboard >}}
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl get pods -n verrazzano-logging

   # Sample output
   NAME                                                      READY   STATUS      RESTARTS      AGE
   opensearch-dashboards-56d845466c-9xsrv                    1/1     Running     0             2h
   opensearch-es-master-0                                    1/1     Running     0             1h
   opensearch-operator-controller-manager-5c498865fc-27jr5   1/1     Running     0             2h
   opensearch-securityconfig-update-jj2xv                    0/1     Completed   0             2h
   ```

</div>
{{< /clipboard >}}
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl get pods -n verrazzano-monitoring

   # Sample output
   NAME                                                   READY   STATUS    RESTARTS   AGE
   prometheus-node-exporter-fstc7                         1/1     Running   0          14h
   prometheus-operator-kube-p-operator-857fb66b74-szv4h   1/1     Running   0          14h
   prometheus-prometheus-operator-kube-p-prometheus-0     3/3     Running   0          14h
   ```

</div>
{{< /clipboard >}}

   These pods in the `verrazzano-system`, `verrazzano-logging`, `verrazzano-monitoring` namespaces constitute the logging and monitoring stack created by Verrazzano for the deployed applications.

   The logging and monitoring infrastructure comprises several components:
   * `opensearch-es` - OpenSearch for log collection
   * `vmi-system-grafana` - Grafana for metric visualization
   * `vms-system-kiali` - Kiali for management console of `istio` service mesh
   * `opensearch-dashboards` - OpenSearch Dashboards for log visualization
   * `prometheus-prometheus-operator-kube-p-prometheus` - Prometheus for metric collection
   <p/>

1. Diagnose failures.

   View the event logs of any pod not entering the `Running` state within
   a reasonable length of time, such as five minutes.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl describe pod -n hello-helidon -l app=hello-helidon
   ```

</div>
{{< /clipboard >}}

   Use the specific namespace and name for the pod being investigated.

### Explore the application

Follow these steps to explore the application's functionality.
If DNS was not configured, then use the alternative commands.

1.  Save the host name and IP address of the load balancer exposing the application's REST service endpoints for later.
{{< clipboard >}}
<div class="highlight">

   ```
    $ HOST=$(kubectl get gateways.networking.istio.io hello-helidon-hello-helidon-gw \
          -n hello-helidon \
          -o jsonpath='{.spec.servers[0].hosts[0]}')
    $ ADDRESS=$(kubectl get service \
          -n istio-system istio-ingressgateway \
          -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
   ```

</div>
{{< /clipboard >}}

    **NOTE**:

    * The value of `ADDRESS` is used only if DNS has not been
    configured.
    * The following alternative commands may not work in conjunction
    with firewalls that validate `HTTP Host` headers.


1.  Get the default message.
{{< clipboard >}}
<div class="highlight">

  ```
    $ curl -sk \
        -X GET \
        "https://${HOST}/greet"

    # Expected response
    {"message":"Hello World!"}
  ```
</div>
{{< /clipboard >}}

    If DNS has not been configured, then use this command.

{{< clipboard >}}
<div class="highlight">

  ```
    $ curl -sk \
        -X GET \
        "https://${HOST}/greet" \
        --resolve ${HOST}:443:${ADDRESS}
  ```
</div>
{{< /clipboard >}}

2.  Get a message for Robert.
{{< clipboard >}}
<div class="highlight">

  ```
    $ curl -sk \
        -X GET \
        "https://${HOST}/greet/Robert"

    # Expected response
    {"message":"Hello Robert!"}
    ```
    If DNS has not been configured, then use this command.
    ```
    $ curl -sk \
        -X GET
        "https://${HOST}/greet/Robert" \
        --resolve ${HOST}:443:${ADDRESS}
   ```

</div>
{{< /clipboard >}}

1.  Update the default greeting.
{{< clipboard >}}
<div class="highlight">

  ```
    $ curl -sk \
        -X PUT \
        "https://${HOST}/greet/greeting" \
        -H 'Content-Type: application/json' \
        -d '{"greeting" : "Greetings"}'
   ```

</div>
{{< /clipboard >}}

    If DNS has not been configured, then use this command.
{{< clipboard >}}
<div class="highlight">

  ```
    $ curl -sk \
        -X PUT \
        "https://${HOST}/greet/greeting" \
        -H 'Content-Type: application/json' \
        -d '{"greeting" : "Greetings"}' \
        --resolve ${HOST}:443:${ADDRESS}
  ```

</div>
{{< /clipboard >}}


1.  Get the new message for Robert.
{{< clipboard >}}
<div class="highlight">

  ```
    $ curl -sk \
        -X GET \
        "https://${HOST}/greet/Robert"

    # Expected response
    {"message":"Greetings Robert!"}
   ```

</div>
{{< /clipboard >}}

    If DNS has not been configured, then use this command.
{{< clipboard >}}
<div class="highlight">

  ```
    $ curl -sk \
        -X GET \
        "https://${HOST}/greet/Robert" \
        --resolve ${HOST}:443:${ADDRESS}
   ```

</div>
{{< /clipboard >}}

### Access the application's logs

Deployed applications have log collection enabled.
These logs are collected using OpenSearch and can be accessed using OpenSearch Dashboards.
OpenSearch and OpenSearch Dashboards are examples of infrastructure Verrazzano creates in support of an application as a
result of applying an application configuration. For more information on creating an index pattern
and visualizing the log data collected in OpenSearch, see [OpenSearch Dashboards]({{< relref "/docs/observability/logging/configure-opensearch#opensearch-dashboards" >}}).

Determine the URL to access OpenSearch Dashboards:
{{< clipboard >}}
<div class="highlight">

 ```
$ OSD_HOST=$(kubectl get ingress \
      -n verrazzano-system opensearch-dashboards \
      -o jsonpath='{.spec.rules[0].host}')
$ OSD_URL="https://${OSD_HOST}"
$ echo "${OSD_URL}"
$ open "${OSD_URL}"
```

</div>
{{< /clipboard >}}

The user name to access OpenSearch Dashboards defaults to `verrazzano` during the Verrazzano installation.

Determine the password to access OpenSearch Dashboards:
{{< clipboard >}}
<div class="highlight">

```
$ echo $(kubectl get secret \
      -n verrazzano-system verrazzano \
      -o jsonpath={.data.password} | base64 \
      --decode)
```

</div>
{{< /clipboard >}}

### Access the application's metrics

Deployed applications have metric collection enabled.
Grafana can be used to access these metrics collected by Prometheus.
Prometheus and Grafana are additional components Verrazzano creates as a result of
applying an application configuration. For more information on visualizing Prometheus
metrics data, see [Grafana]({{< relref "/docs/observability/monitoring/configure/grafana/_index.md" >}}).

Determine the URL to access Grafana:
{{< clipboard >}}
<div class="highlight">

```
$ GRAFANA_HOST=$(kubectl get ingress \
      -n verrazzano-system vmi-system-grafana \
      -o jsonpath='{.spec.rules[0].host}')
$ GRAFANA_URL="https://${GRAFANA_HOST}"
$ echo "${GRAFANA_URL}"
$ open "${GRAFANA_URL}"
```

</div>
{{< /clipboard >}}

The user name to access Grafana is set to the default value `verrazzano` during the Verrazzano installation.

Determine the password to access Grafana:
{{< clipboard >}}
<div class="highlight">

```
$ echo $(kubectl get secret \
      -n verrazzano-system verrazzano \
      -o jsonpath={.data.password} | base64 \
      --decode)
```

</div>
{{< /clipboard >}}

Alternatively, metrics can be accessed directly using Prometheus.
Determine the URL for this access:
{{< clipboard >}}
<div class="highlight">

```
$ PROMETHEUS_HOST=$(kubectl get ingress \
      -n verrazzano-system vmi-system-prometheus \
      -o jsonpath='{.spec.rules[0].host}')
$ PROMETHEUS_URL="https://${PROMETHEUS_HOST}"
$ echo "${PROMETHEUS_URL}"
$ open "${PROMETHEUS_URL}"
```

</div>
{{< /clipboard >}}

The user name and password for both Prometheus and Grafana are the same.

### Suppress Kiali console warnings

For some applications, the Kiali console may show warnings for VirtualService and Gateway objects that replicate hostname/port configurations across multiple IngressTraits. These warnings do not impact functionality and can be suppressed with the following component override:
{{< clipboard >}}
<div class="highlight">

```
kiali:
  overrides:
    - values:
        kiali_feature_flags:
          validations:
            ignore: ["KIA1106", "KIA0301"]
```

</div>
{{< /clipboard >}}

## Remove the application

Run the following commands to delete the application configuration, and optionally the component and namespace.

1. Delete the application configuration.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl delete -f {{< release_source_url raw=true path="examples/hello-helidon/hello-helidon-app.yaml" >}}
   ```

</div>
{{< /clipboard >}}


   The deletion of the application configuration will result in the destruction
   of all application-specific Kubernetes objects.

1. (Optional) Delete the application's component.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl delete -f {{< release_source_url raw=true path="examples/hello-helidon/hello-helidon-comp.yaml" >}}
   ```

</div>
{{< /clipboard >}}

   **NOTE**: This step is not required if other application configurations for this component will be applied in the future.

1. (Optional) Delete the namespace.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl delete namespace hello-helidon
   ```

</div>
{{< /clipboard >}}
