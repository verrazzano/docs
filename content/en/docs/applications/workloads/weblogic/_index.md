---
title: "WebLogic"
description: "Developing WebLogic applications with Verrazzano"
weight: 6
draft: true
---

## WebLogic Kubernetes Operator

WebLogic server platform is a widely used enterprise application server for managing Java Enterprise Edition ("JEE") based applications and is [certified](https://blogs.oracle.com/weblogicserver/weblogic-server-certification-on-kubernetes) to run on Kubernetes using the [WebLogic Kubernetes Operator](https://github.com/oracle/weblogic-kubernetes-operator). WebLogic Kubernetes Operator manages the WebLogic Domain life cycle in a Verrazzano. WebLogic Domain CRD specifies configuration of a WebLogic Domain. The Operator watches WebLogic Domain CR and reconciles WebLogic Domain by creating, updating, and deleting Kubernetes resources (Pods, services and so on) as needed. Each pod is a WebLogic Domain server (administration or managed).

<figure>
  <img src="/docs/images/wls-op-action.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="WebLogic Kubernetes Operator"/>
  <figcaption style="text-align:center">WebLogic Kubernetes Operator</figcaption>
</figure>

## WebLogic Kubernetes Operator in Verrazzano

 WebLogic Kubernetes Operator is installed in the `verrazzano-system` namespace and is also part of the [istio-mesh](https://istio.io/latest/about/service-mesh/) deployed by Verrazzano.

<figure>
  <img src="/docs/images/wls-op-install.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="WebLogic Kubernetes Operator in Verrazzano"/>
  <figcaption style="text-align:center">WebLogic Kubernetes Operator in Verrazzano</figcaption>
</figure>

## WebLogic OAM Component

The WebLogic workloads are specified as [VerrazzanoWebLogicWorkload]({{< relref "/docs/reference/API/OAM/Workloads#verrazzanoweblogicworkload" >}}) OAM Component in Verrazzano and one component specifies exactly one WebLogic domain. An `ApplicationConfiguration` can contain multiple `VerrazzanoWebLogicWorkload` Components and hence multiple WebLogic Domains. `Traits` can be specified for one or more `VerrazzanoWebLogicWorkload` components. All WebLogic Domain CRD fields can be specified in `VerrazzanoWebLogicWorkload`.
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

## Example WebLogic OAM Component

Following is an example WebLogic OAM Component.

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


## WebLogic in Verrazzano - Verrazzano Application Operator

Verrazzano Application Operator watches the `VerrazzanoWebLogicWorkload` CR and creates, updates, and deletes the `Domain` CR based upon the specification provided in the `VerrazzanoWebLogicWorkload` CR. It also modifies the WebLogic Domain CR to add Fluentd sidecar injection for logging and Monitoring Exporter config, if it doesn’t exist already, for metrics. WebLogic Kubernetes Operator will create the WebLogic Domain based on the WebLogic Domain CR.

<figure>
  <img src="/docs/images/wls-app-operator.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="Verrazzano Application Operator"/>
  <figcaption style="text-align:center">Verrazzano Application Operator</figcaption>
<figure>

## WebLogic Domain life ycle

Following are the different life cycle stages of a WebLogic Domain.

1. Create WebLogic Domain
- Application containing WebLogic component is created
- WebLogic component added to existing application
2. Delete WebLogic Domain
- Application containing WebLogic component deleted
- WebLogic component removed from existing application
3. Scale WebLogic Domain
- Modify the replicas field in the WebLogic Domain CR within the OAM component spec
- Automatic scaling currently not supported by Verrazzano
4. Update WebLogic Domain
- Modify the other fields field in the WebLogic Domain CR within the OAM component spec

WebLogic Domain scale-in and scale-out operations can be performed by modifying the OAM component replicas count. WebLogic Domain can be deleted by deleting the OAM application or removing component from application.

<figure>
  <img src="/docs/images/wls-domain-scale.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="WebLogic Domain life cycle"/>
  <figcaption style="text-align:center">WebLogic Domain life cycle</figcaption>
<figure>

## Istio Integration

Verrazzano creates all WebLogic Domain pods in istio-mesh and all  WebLogic network traffic uses [mTLS](https://codeburst.io/mutual-tls-authentication-mtls-de-mystified-11fa2a52e9cf).

<figure>
  <img src="/docs/images/wls-domain-mtls.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="WebLogic Domain mTLS"/>
  <figcaption style="text-align:center">WebLogic Domain mTLS</figcaption>
<figure>
<br/>
The Envoy proxy sidecar exists in front of workloads for each service providing security, load balancing, metrics and so on. Traffic in and out of the pod goes through the proxy. 

<figure>
  <img src="/docs/images/wls-istio-mesh.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="WebLogic Domain in Istio-Mesh"/>
  <figcaption style="text-align:center">WebLogic Domain in Istio-Mesh</figcaption>
<figure>
<br/>
Istio will automatically put WebLogic Domain in the [istio-mesh](#istio-integration) if namespace has label `istio-injection=enabled`. All the namespaces where the WebLogic Domain is to be created should be labelled `istio-injection=enabled` else the WebLogic Domain creation will fail. We can also label the namespaces when using `VerrazzanoProject` which will by default assign the label to all namespaces associated with the project. In the WebLogic Domain CR, Verrazzano Application Operator sets the Istio enabled field.

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

## WebLogic Domain - Istio Mesh Ingress and Egress

Verrazzano installer creates the Ingress Gateway Service. Ingress gateway is `LoadBalancer` service type and TLS is terminated at Istio Ingress Gateway. Ingress to WebLogic Domain is optional and `IngressTrait` can be used to enable that.

<figure>
  <img src="/docs/images/wls-istio-ing-eg.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="Istio Mesh Ingress and Egress"/>
  <figcaption style="text-align:center">Istio Mesh Ingress and Egress</figcaption>
<figure>

## Istio Ingress and Routing – Single WebLogic Domain

Istio Gateway resource describes a proxy providing ingress into the Kubernetes cluster and the istio-mesh. Gateway specifies the host, port,protocol and so on and is bound to a gateway service (LoadBalancer / NodePort). VirtualService specifies routes to services, load balancing.

<figure>
  <img src="/docs/images/wls-istio-gateway.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="Istio: Single WebLogic Domain"/>
  <figcaption style="text-align:center">Istio: Single WebLogic Domain</figcaption>
<figure>

### Istio Ingress – Example ToDo List Gateway

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

### Istio Ingress – Example ToDo List VirtualService

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

## Istio Ingress and Routing – Multiple WebLogic Domains

Multiple `Gateway` resources use the same Istio Ingress Gateway service. Verrazzano always creates single `Gateway` and `VirtualService` per `IngressTrait` specified on the OAM Component.

<figure>
  <img src="/docs/images/wls-istio-multidomain.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="Istio: Multiple WebLogic Domains"/>
  <figcaption style="text-align:center">Istio: Multiple WebLogic Domains</figcaption>
<figure>

## Istio Authorization Policy

The Istio `AuthorizationPolicy` resource specifies access controls for WebLogic pods, other pods in the application, Ingress gateway and Prometheus.

<figure>
  <img src="/docs/images/wls-istio-auth.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="Istio AuthorizationPolicy"/>
  <figcaption style="text-align:center">Istio AuthorizationPolicy</figcaption>
<figure>

### Example Istio Authorization Policy

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

## WebLogic Metrics

Prometheus scrapes each WebLogic pod on the metrics port periodically. 

<figure>
  <img src="/docs/images/wls-metrics-prom.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="WebLogic Metrics"/>
  <figcaption style="text-align:center">WebLogic Metrics</figcaption>
<figure>

Verrazzano will inject `MetricsTrait` into AppConfig if the trait doesn’t exist. WebLogic Monitoring Exporter sidecar provides metrics endpoint. Verrazzano will inject default Monitoring Exporter config into WebLogic Domain CR if it doesn’t exist. Verrazzano Application Operator updates ***Prometheus*** Configmap with WebLogic targets and Verrazzano installs ***Grafana*** dashboards to view WebLogic metrics. WebLogic Kubernetes Operator configures the ***Monitoring Exporter*** using a REST API and labels the pods with metrics-related labels. Metrics scraped at /metrics on port 8080.

<figure>
  <img src="/docs/images/wls-metrics-exporter.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="WebLogic Monitoring Exporter"/>
  <figcaption style="text-align:center">WebLogic Monitoring Exporter</figcaption>
<figure>

### WebLogic Metrics – AppConfig Default Injection

Example `MetricsTrait` from TodoList `ApplicationConfiguration`; Verrazzano will inject default `MetricsTrait` if missing from `ApplicationConfiguration`.

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

### WebLogic Metrics – Component Monitoring Exporter

Example monitoringExporter configuration in OAM component.

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

### WebLogic Metrics – Pod annotations

Following annotations can be used for enabling metrics on pods.
- `prometheus.io/metricsEnabled: "true”` : Enable metrics scraping
- `prometheus.io/metricsPath: /metrics` : Specify Metrics scraping path
- `prometheus.io/metricsPort: ”8080"` : Specify Metrics scraping port

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

WebLogic logs are sent to the Elasticsearch installed in the Verrazzano cluster. The Fluentd sidecar is injected into each WebLogic pod to send server logs to stdout. The Fluentd `DaemonSet` in `verrazzano-system` namespace sends logs to the Elasticsearch. Logs are indexed by namespace in ElasticSearch. All the configuration is done automatically by Verrazzano.

<figure>
  <img src="/docs/images/wls-logging.png" style="display:block;margin-left:auto;margin-right:auto;width:50%" alt="WebLogic Logging"/>
  <figcaption style="text-align:center">WebLogic Logging</figcaption>
<figure>

## Lift and Shift WebLogic applications

Verrazzano makes it easy for WebLogic application to migrate from on-premises installations to the cloud. WebLogic Deploy Tooling (WDT) can be used to build the domain model and WebLogic Image Tool (WIT) can be used to build the WebLogic Domain image.

<figure>
  <img src="/docs/images/wls-lift-and-shift.png" style="display:block;margin-left:auto;margin-right:auto;width:70%" alt="Lift-and-Shift"/>
  <figcaption style="text-align:center">Lift-and-Shift</figcaption>
<figure>

See the [lift-and-shift]({{< relref "/docs/samples/lift-and-shift.md" >}}) guide for detailed instructions.

## Step-By-Step instructions on Deploying WebLogic applications in Verrazzao.

1. **Create WebLogic Domain image**: To deploy a WebLogic Domain in Kubernetes, we first need to create a Docker Image for the WebLogic Domain. For example follow the instructions given in [Example Image with a WLS Domain](https://github.com/oracle/docker-images/tree/main/OracleWebLogic/samples/12213-domain-home-in-image-wdt) to create a WebLogic Domain image using [Oracle WebLogic Deploy Tooling (WDT)](https://github.com/oracle/weblogic-deploy-tooling).
2. **Create VerrazzanoWebLogicWorkload Component**: In order to deploy and run the WebLogic Domain image in Verrazzano, create the ***VerrazzanoWebLogicWorkload*** Component that specifies the definition and parameters for the WebLogic Domain contained in the image. See [todo-domain example]({{< relref "/docs/reference/API/OAM/Workloads#verrazzanoweblogicworkload" >}}) for the example ***VerrazzanoWebLogicWorkload*** Component resource created for a sample WebLogic Domain. For all the option supported by the WebLogic Domain configuration, see [Domain.md](https://github.com/oracle/weblogic-kubernetes-operator/blob/main/documentation/domains/Domain.md).
3. **Create ApplicationConfiguration for WebLogic application**: Next we create an ***ApplicationConfiguration*** that uses the ***VerrazzanoWebLogicWorkload*** Component we created for the WebLogic Domain. See [todo application]({{< relref "/docs/samples/todo-list.md" >}}) for an example ***ApplicationConfiguration*** using a ***VerrazzanoWebLogicWorkload*** Component.
4. **Verify Domain**: Verrazzano creates the underlying ***Domain*** Kubernetes resource from the ***VerrazzanoWebLogicWorkload*** Component which is further processed by the ***WebLogic Kubernetes Operator*** to create admin/managed server pods and deploy the applications/resources associated with the WebLogic Domain. Simplest way to verify that the WebLogic Domain is up and running is to follow the steps mentioned in [verify-the-domain](https://oracle.github.io/weblogic-kubernetes-operator/samples/simple/domains/domain-home-in-image/#verify-the-domain) section.


## Database Connection

WebLogic applications typically make database connections using the connection information present in the ***JDBCSystemResources*** created in WebLogic Domain. In order to implement this in Verrazzano, databases will deployed as separate components and the connection information made available to the WebLogic Domain using the WDT Model.

1. **Deploy the Database in Verrazzano**: To deploy a database, we need to create the corresponding ***Component*** and ***ApplicationConfiguration*** that will run the database in a pod and expose its connection information as a ***Service***. For example, look at [tododomain-mysql]({{< relref "/docs/samples/todo-list.md" >}}) descriptor.
1. **Create WebLogic resource ConfigMap**: Next we create a ***ConfigMap*** that will contain the definition of ***JDBCSystemResource*** with connection information for the database.. For example, see the definition of ***tododomain-configmap*** in [sample application configuration]({{< relref "/docs/samples/todo-list.md" >}}).
1. **Configure WebLogic Domain to use the WebLogic resource ConfigMap**: The ***ConfigMap*** containing resource information for ***JDBCSystemResource*** can be configured in the ***configuration*** section of the ***VerrazzanoWebLogicWorkload*** Component of the WebLogic Domain.
   
```yaml
...
    configuration:
        introspectorJobActiveDeadlineSeconds: 900
        model:
            configMap: tododomain-configmap
            domainType: WLS
...
```

See [sample application configuration]({{< relref "/docs/samples/todo-list.md" >}}) for more details.

## Ingresses

To access the endpoints for a JEE application deployed as part of a ***VerrazzanoWebLogicWorkload*** Component, Verrazzano provides a feature to specify an ***IngressTrait*** for the Component which is then translated to an [Istio Ingress Gateway](https://istio.io/latest/docs/reference/config/networking/gateway/) and [VirtualService](https://istio.io/latest/docs/reference/config/networking/virtual-service/) by Verrazzano. For example, look at [sample application]({{< relref "/docs/samples/todo-list.md" >}}) where the ***IngressTrait*** is configured for the application endpoint.

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

The endpoint can then be accessed using the Istio Gateway created by Verrazzano, as described in [Access the ToDo List application]({{< relref "/docs/samples/todo-list.md" >}}) section.

```
$ HOST=$(kubectl get gateway -n todo-list -o jsonpath={.items[0].spec.servers[0].hosts[0]})
$ ADDRESS=$(kubectl get service -n istio-system istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
$ curl -sk https://${HOST}/todo/ --resolve ${HOST}:443:${ADDRESS}
```

## References

- [WebLogic Kubernetes Operator doc](https://oracle.github.io/weblogic-kubernetes-operator/)
- [WebLogic Kubernetes Operator GitHub](https://github.com/oracle/weblogic-kubernetes-operator/)
- [WebLogic Domain CRD reference](https://github.com/oracle/weblogic-kubernetes-operator/blob/main/documentation/domains/Domain.md)
- [Verrazzano Application Workloads](https://verrazzano.io/docs/applications/workloads/)
- [Lift and Shift doc](https://verrazzano.io/docs/samples/lift-and-shift/)



