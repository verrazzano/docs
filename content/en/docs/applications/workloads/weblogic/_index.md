---
title: "WebLogic Workload"
linktitle: "WebLogic"
description: "Develop WebLogic applications with Verrazzano"
weight: 6
draft: false
---

WebLogic Server is a widely-used enterprise application server for managing Java Enterprise Edition-based applications and is [certified](https://blogs.oracle.com/weblogicserver/weblogic-server-certification-on-kubernetes) to run on Kubernetes using the [WebLogic Kubernetes Operator](https://oracle.github.io/weblogic-kubernetes-operator/). The WebLogic Kubernetes Operator manages the WebLogic domain life cycle in Verrazzano. The WebLogic Domain custom resource definition (CRD) specifies the configuration of the WebLogic domain. The operator monitors the WebLogic Domain CRD and reconciles the domain by creating, updating, and deleting Kubernetes resources (Pods, Services, and such), as needed. Each pod is a WebLogic Server, an Administration Server or Managed Server.

<figure>
  <img src="/docs/images/wls-op-action.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="WebLogic Kubernetes Operator"/>
  <figcaption style="text-align:center">WebLogic Kubernetes Operator</figcaption>
</figure>


 The WebLogic Kubernetes Operator is installed in the `verrazzano-system` namespace and is also part of the [istio-mesh](https://istio.io/latest/about/service-mesh/) deployed by Verrazzano.

<figure>
  <img src="/docs/images/wls-op-install.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="WebLogic Kubernetes Operator in Verrazzano"/>
  <figcaption style="text-align:center">WebLogic Kubernetes Operator in Verrazzano</figcaption>
</figure>

## WebLogic OAM Component

In Verrazzano, WebLogic workloads are specified as a [VerrazzanoWebLogicWorkload]({{< relref "/docs/reference/API/OAM/Workloads#verrazzanoweblogicworkload" >}}) OAM Component and one component specifies exactly one WebLogic domain. An `ApplicationConfiguration` can contain multiple `VerrazzanoWebLogicWorkload` components and therefore, multiple WebLogic domains. You can specify `Traits` for one or more `VerrazzanoWebLogicWorkload` components. All WebLogic Domain CRD fields can be specified in the `VerrazzanoWebLogicWorkload`.
<table>
  <tr style="background-color: #ffffff;">
  <td>
    <figure>
      <img src="/docs/images/wls-app-config.png" style="display:block;margin-left:auto;margin-right:auto;width:50%" alt="WebLogic Domain ApplicationConfiguration"/>
      <figcaption style="text-align:center">WebLogic Domain ApplicationConfiguration</figcaption>
    <figure>
  </td>
  <td>
    <figure>
      <img src="/docs/images/wls-app-component.png" style="display:block;margin-left:auto;margin-right:auto;width:50%" alt="WebLogic Domain Component"/>
      <figcaption style="text-align:center">WebLogic Domain Component</figcaption>
    <figure>
  </td>
  </tr>
</table>


The following is an example WebLogic OAM Component.

```yaml
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:…
spec:  
  workload:    
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: VerrazzanoWebLogicWorkload
    spec:      
      template:
 metadata:
    name: todo-domain
 spec:
           domainUID: tododomain
           omainHome: /u01/domains/tododomain          …

```


## Verrazzano application operator

The Verrazzano application operator monitors the `VerrazzanoWebLogicWorkload` custom resource (CR) and creates, updates, and deletes the `Domain` CR based on the specification provided in the `VerrazzanoWebLogicWorkload` CR. Also, it modifies the WebLogic Domain CRD to add Fluentd sidecar injection for logging and a Monitoring Exporter configuration for metrics, if they do not already exist. The WebLogic Kubernetes Operator creates the WebLogic domain based on the WebLogic Domain CRD.

<figure>
  <img src="/docs/images/wls-app-operator.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="Verrazzano Application Operator"/>
  <figcaption style="text-align:center">Verrazzano Application Operator</figcaption>
<figure>

## WebLogic domain life cycle

The following are the life cycle stages of a WebLogic domain:

1. Create a WebLogic domain.
   - Application containing WebLogic component is created.
   - WebLogic component added to an existing application.
2. Delete a WebLogic domain.
   - Application containing WebLogic component is deleted.
   - WebLogic component removed from an existing application.
3. Scale a WebLogic domain.
   - Modify the `replicas` field in the WebLogic Domain CRD within the OAM component spec.
4. Update a WebLogic domain.
   - Modify the other `fields` field in the WebLogic Domain CRD within the OAM component spec.

Scale-in and scale-out a WebLogic domain by modifying the OAM component replicas count. Delete the WebLogic domain by deleting the OAM application or removing the component from the application.

<figure>
  <img src="/docs/images/wls-domain-scale.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="WebLogic Domain life cycle"/>
  <figcaption style="text-align:center">WebLogic Domain Life Cycle</figcaption>
<figure>

## Istio integration

Verrazzano creates all WebLogic domain pods in an Istio mesh; all WebLogic network traffic uses [mTLS](https://codeburst.io/mutual-tls-authentication-mtls-de-mystified-11fa2a52e9cf).

<figure>
  <img src="/docs/images/wls-domain-mtls.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="WebLogic Domain mTLS"/>
  <figcaption style="text-align:center">WebLogic Domain mTLS</figcaption>
<figure>
<br/>
The Envoy proxy sidecar exists in front of workloads for each service providing security, load balancing, metrics, and such. Traffic in and out of the pod goes through the proxy.

<figure>
  <img src="/docs/images/wls-istio-mesh.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="WebLogic Domain in Istio-Mesh"/>
  <figcaption style="text-align:center">WebLogic Domain in Istio-Mesh</figcaption>
<figure>
<br/>
If the namespace is labeled `istio-injection=enabled`, then Istio puts the WebLogic domain in the Istio mesh. You should label all the namespaces where the WebLogic domain is to be created, `istio-injection=enabled`, or WebLogic domain creation will fail. Also, you can label the namespaces when using `VerrazzanoProject`, which by default, assigns the label to all the namespaces associated with the project. In the WebLogic Domain CRD, the Verrazzano application operator sets the Istio enabled field.

```yaml
apiVersion: v1
items:
- apiVersion: weblogic.oracle/v8
  kind: Domain
  …
  spec:
     …
      istio:
        enabled: true
```

### Istio mesh ingress and egress

The Verrazzano installer creates the ingress gateway service. The Ingress gateway is a `LoadBalancer` service; TLS is terminated at the Istio ingress gateway. Ingress to the WebLogic domain is optional; you can use an `IngressTrait` to enable it.

<figure>
  <img src="/docs/images/wls-istio-ing-eg.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="Istio Mesh Ingress and Egress"/>
  <figcaption style="text-align:center">Istio Mesh Ingress and Egress</figcaption>
<figure>

### Istio ingress and routing for a single WebLogic domain

The Istio Gateway resource describes a proxy providing ingress to the Kubernetes cluster and the Istio mesh. The Gateway specifies the host, port, protocol, and so on, and is bound to a gateway service (LoadBalancer/NodePort). `VirtualService` specifies routes to services and load balancing.

<figure>
  <img src="/docs/images/wls-istio-gateway.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="Istio: Single WebLogic Domain"/>
  <figcaption style="text-align:center">Istio: Single WebLogic Domain</figcaption>
<figure>


Example of an Istio `Gateway` resource:

```yaml
apiVersion: networking.istio.io/v1beta1
  kind: Gateway
…
 spec:
    selector:
      istio: ingressgateway
    servers:
    - hosts:
      - todo-appconf.todo-list.172.18.0.230.nip.io #Host for this gateway server
      port:
        name: https
        number: 443
        protocol: HTTPS
      tls:
        credentialName: todo-list-todo-appconf-cert-secret #Secret containing TLS certificate
        mode: SIMPLE #Terminate TLS

```


Example of an Istio `VirtualService` resource:

```yaml
apiVersion: networking.istio.io/v1beta1
  kind: VirtualService
…
  spec:
    gateways:
    - todo-list-todo-appconf-gw #Gateway resource reference
    hosts:
    - todo-appconf.todo-list.172.18.0.230.nip.io #Host that this VS applies to.  Gateway resource can have multiple hosts
    http:
    - match:
      - uri:
          prefix: /todo
      route:
      - destination:
          host: tododomain-adminserver #Back-end Kubernetes Service
          port:
            number: 7001

```

### Istio ingress and routing for multiple WebLogic domains

Multiple `Gateway` resources use the same Istio ingress gateway service. Verrazzano creates a single `Gateway` and `VirtualService` per `IngressTrait` specified on the OAM Component.

<figure>
  <img src="/docs/images/wls-istio-multidomain.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="Istio: Multiple WebLogic Domains"/>
  <figcaption style="text-align:center">Istio: Multiple WebLogic Domains</figcaption>
<figure>

### Istio authorization policy

The Istio `AuthorizationPolicy` resource specifies access controls for WebLogic pods, other pods in the application, the Ingress gateway, and Prometheus.

<figure>
  <img src="/docs/images/wls-istio-auth.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="Istio AuthorizationPolicy"/>
  <figcaption style="text-align:center">Istio AuthorizationPolicy</figcaption>
<figure>

Example Istio authorization policy

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
...
spec:
  rules:
  - from:
    - source:
        principals:
        - cluster.local/ns/todo-list/sa/todo-appconf
        - cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account
        - cluster.local/ns/verrazzano-system/sa/verrazzano-monitoring-operator
        - cluster.local/ns/verrazzano-system/sa/weblogic-operator-sa
  selector:
    matchLabels:
      verrazzano.io/istio: todo-appconf

```

## WebLogic metrics

Prometheus scrapes each WebLogic pod on the metrics port periodically.

<figure>
  <img src="/docs/images/wls-metrics-prom.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="WebLogic Metrics"/>
  <figcaption style="text-align:center">WebLogic Metrics</figcaption>
<figure>

If the trait doesn’t exist, Verrazzano will inject the `MetricsTrait` into `AppConfig`. The WebLogic Monitoring Exporter sidecar provides the metrics endpoint. If it doesn’t already exist, Verrazzano will inject the default Monitoring Exporter configuration into the WebLogic Domain CRD. The Verrazzano application operator updates the Prometheus Configmap with WebLogic targets and Verrazzano installs Grafana dashboards to view WebLogic metrics. The WebLogic Kubernetes Operator configures the Monitoring Exporter using a REST API and labels the pods with metrics-related labels. Metrics are scraped at `/metrics` on port 8080.

<figure>
  <img src="/docs/images/wls-metrics-exporter.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="WebLogic Monitoring Exporter"/>
  <figcaption style="text-align:center">WebLogic Monitoring Exporter</figcaption>
<figure>

### AppConfig default injection

Example `MetricsTrait` from the TodoList `ApplicationConfiguration`. If missing from `ApplicationConfiguration`, Verrazzano will inject the default `MetricsTrait`.

```yaml
kind: ApplicationConfiguration
metadata:
  name: todo-appconf
...
spec:
  components:
    - componentName: todo-domain
      traits:
        - trait:
            apiVersion: oam.verrazzano.io/v1alpha1
            kind: MetricsTrait
            spec:
  …

```
### Monitoring Exporter Component

Example `monitoringExporter` configuration in OAM component.

```yaml
workload:
  apiVersion: oam.verrazzano.io/v1alpha1
  kind: VerrazzanoWebLogicWorkload
…
monitoringExporter:
  imagePullPolicy: IfNotPresent
  configuration:    
     metricsNameSnakeCase: true
     domainQualifier: true
     queries:      
     - key: name
       keyName: location
       prefix: wls_server_
…
```

### Pod annotations

The following annotations can be used for enabling metrics on pods.
- `prometheus.io/metricsEnabled: "true”` - Enables metrics scraping.
- `prometheus.io/metricsPath: /metrics` - Specifies metrics scraping path.
- `prometheus.io/metricsPort: ”8080"` - Specifies metrics scraping port.

Example:

```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    prometheus.io/path: /metrics
    prometheus.io/port: "8080"
    prometheus.io/scrape: "true"

```

## Logging

WebLogic logs are sent to Elasticsearch, which is installed in the Verrazzano cluster. The Fluentd sidecar is injected into each WebLogic pod to send server logs to stdout. The Fluentd `DaemonSet` in the `verrazzano-system` namespace sends logs to Elasticsearch. In Elasticsearch, logs are indexed by namespace.

<figure>
  <img src="/docs/images/wls-logging.png" style="display:block;margin-left:auto;margin-right:auto;width:50%" alt="WebLogic Logging"/>
  <figcaption style="text-align:center">WebLogic Logging</figcaption>
<figure>

## Lift-and-Shift WebLogic applications

Verrazzano makes it easy for you to migrate WebLogic applications from on-premises installations to the cloud. You can use WebLogic Deploy Tooling (WDT) to build the domain model and WebLogic Image Tool (WIT) to build the WebLogic domain image.

<figure>
  <img src="/docs/images/wls-lift-and-shift.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="Lift-and-Shift"/>
  <figcaption style="text-align:center">Lift-and-Shift</figcaption>
<figure>

For detailed instructions, see the [Lift-and-Shift]({{< relref "/docs/samples/lift-and-shift.md" >}}) Guide.

## Deploy WebLogic applications in Verrazzano

Step 1. Create a WebLogic domain image.
   - To deploy a WebLogic domain in Kubernetes, first you need to create a Docker image for the WebLogic domain.
   - To create a WebLogic domain image using [WebLogic Deploy Tooling](https://github.com/oracle/weblogic-deploy-tooling) (WDT), follow the instructions in [Example Image with a WLS Domain](https://github.com/oracle/docker-images/tree/main/OracleWebLogic/samples/12213-domain-home-in-image-wdt).

Step 2. Create a VerrazzanoWebLogicWorkload component.
   - To deploy and run the WebLogic domain image in Verrazzano, create the VerrazzanoWebLogicWorkload component that specifies the definition and parameters for the WebLogic domain contained in the image.
   - For an example VerrazzanoWebLogicWorkload component resource created for a sample WebLogic domain, see the [todo-domain]({{< relref "/docs/reference/API/OAM/Workloads#verrazzanoweblogicworkload" >}}) example.
   - For all the option supported by the WebLogic domain configuration, see [Domain.md](https://github.com/oracle/weblogic-kubernetes-operator/blob/main/documentation/domains/Domain.md).

Step 3. Create ApplicationConfiguration for WebLogic application.
   - Next, create an ApplicationConfiguration that uses the VerrazzanoWebLogicWorkload component you created for the WebLogic domain.
   - For an example ApplicationConfiguration using a VerrazzanoWebLogicWorkload component, see the [ToDo List]({{< relref "/docs/samples/todo-list.md" >}}) example application.

Step 4. Verify the domain.
   - Verrazzano creates the underlying domain Kubernetes resource from the VerrazzanoWebLogicWorkload component which is then processed by the WebLogic Kubernetes Operator to create the Administration and Managed Server pods, and deploy the applications and resources associated with the WebLogic domain.
   - To verify that the WebLogic domain is up and running, follow the steps found [here](https://oracle.github.io/weblogic-kubernetes-operator/samples/domains/domain-home-in-image/#verify-the-domain).


## Database connections

Typically, WebLogic applications make database connections using the connection information present in the JDBCSystemResources created in a WebLogic domain. To implement this in Verrazzano, databases are deployed as separate components and the connection information is made available to the WebLogic domain using a WDT Model.

Step 1. Deploy the database in Verrazzano.
   - To deploy a database, you need to create the corresponding Component and ApplicationConfiguration that will run the database in a pod and expose its connection information as a Service.
   - For an example, look at the [tododomain-mysql]({{< relref "/docs/samples/todo-list.md" >}}) descriptor.

Step 2. Create a WebLogic resource ConfigMap.
   - Next, create a ConfigMap that will contain the JDBCSystemResource definition with connection information for the database.
   - For an example, see the  `tododomain-configmap` definition in the [ToDo List]({{< relref "/docs/samples/todo-list.md" >}}) example application configuration.

Step 3. Configure the WebLogic domain to use the WebLogic resource ConfigMap.
   - You can configure the ConfigMap, containing the resource information for the JDBCSystemResource, in the configuration section of the VerrazzanoWebLogicWorkload component of the WebLogic domain.

```yaml
...
    configuration:
        introspectorJobActiveDeadlineSeconds: 900
        model:
            configMap: tododomain-configmap
            domainType: WLS
...
```

For more details, see the [ToDo List]({{< relref "/docs/samples/todo-list.md" >}}) example application configuration.

## Ingresses

To access the endpoints for a Java EE application deployed as part of a VerrazzanoWebLogicWorkload component, Verrazzano plets you specify an IngressTrait for the component which is then translated to an [Istio ingress gateway](https://istio.io/latest/docs/reference/config/networking/gateway/) and [VirtualService](https://istio.io/latest/docs/reference/config/networking/virtual-service/). For an example, see the [ToDo List]({{< relref "/docs/samples/todo-list.md" >}}) example application, where the IngressTrait is configured for the application endpoint.

```yaml
...
    - trait:
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: IngressTrait
    spec:
        rules:
        - paths:
            # application todo
            - path: "/todo"
                pathType: Prefix

...
```

Then, you can access the endpoint using the Istio gateway, as described in Step 8. [Access the ToDo List application]({{< relref "/docs/samples/todo-list.md" >}}).

```
$ HOST=$(kubectl get gateway -n todo-list -o jsonpath={.items[0].spec.servers[0].hosts[0]})
$ ADDRESS=$(kubectl get service -n istio-system istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
$ curl -sk https://${HOST}/todo/ --resolve ${HOST}:443:${ADDRESS}
```

## References

- [WebLogic Kubernetes Operator documentation](https://oracle.github.io/weblogic-kubernetes-operator/)
- [WebLogic Kubernetes Operator GitHub repository](https://github.com/oracle/weblogic-kubernetes-operator/)
- [WebLogic Domain CRD](https://github.com/oracle/weblogic-kubernetes-operator/blob/main/documentation/domains/Domain.md)
- [Verrazzano Application Workloads]({{< relref "/docs/applications/workloads/" >}})
- [Lift and Shift Guide](https://verrazzano.io/docs/samples/lift-and-shift/)
