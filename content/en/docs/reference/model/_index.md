---
title: "Verrazzano Application Model"
weight: 1
bookCollapseSection: true
---

The Verrazzano Model (`vm` kubectl resource) is a Kubernetes Custom Resource Definition (CRD) that is added to the Verrazzano management cluster. This CRD describes a "Verrazzano Application," which is made up of one or more components.  Components can be WebLogic domains, Coherence clusters, Helidon microservices, or other generic container workloads.  The model also defines connections between components, ingresses to an application, and connections to external services, such as a database or a REST endpoint. Conceptually, the model captures information about the application which does not vary based on where the application is deployed.  Then a Verrazzano Binding (`vb` kubectl resource) is used to map the Verrazzano Application defined in the model to the deployment environment. For example, the WebLogic domain X always talks to database Y, no matter how many times this application is deployed. In a particular instance or deployment of the application, for example, the "test" instance, there may be different credentials and a different URL to access the test version of Y database, but X always talks to Y. The application ***model*** must define a connection to the database, but the actual credentials and URL used when the application is deployed is defined in the ***binding***. Bindings map the application to the environment.

The combination of a model and binding produces an instance of an application.
Both the model and binding are meant to be sparse; they contain only the information that is needed to deploy the application.  Anything that Verrazzano can infer or use a default value for, can be omitted from these files.

For an example Verrazzano Model, see [demo-model](https://github.com/verrazzano/verrazzano/blob/master/examples/bobs-books/bobs-books-model.yaml).

### Top-Level Attributes

The top-level attributes of a Verrazzano application model define its metadata, version, kind, and spec.

``` yaml
apiVersion: verrazzano.io/v1beta1
kind: VerrazzanoModel
metadata:
  name: hello-world-model
  namespace: default
spec:
  ...
```

| Attribute | Type | Required | Default Value | Description |
|-----------|------|----------|---------------|-------------|
| `apiVersion` | `string` | Y || A string that identifies the version of the schema the object should have. The core types uses `verrazzano.io/v1beta1` in this version of specification. |
| `kind` | `string` | Y || Must be `VerrazzanoModel` |
| `metadata` | [`ObjectMeta`](https://v1-16.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.16/#objectmeta-v1-meta) | Y | | Information about the model. |
| `spec`| [`Spec`](#spec) | Y || A specification for application model attributes. |

### Spec

The specification defines a Verrazzano application model.

``` yaml
spec:
  description: Hello World application
  weblogicDomains:
    - name: hello-weblogic
      ...
  coherenceClusters:
    - name: hello-coherence
      ...
  helidonApplications:
    - name: hello-helidon
      ...
```

| Attribute | Type | Required | Default Value | Description |
|-----------|------|----------|---------------|-------------|
| `description` | `string` | Y || Description of the model. |
| `weblogicDomains` | [`[]WebLogicDomain`](#weblogicdomain) | N || WebLogic Server domain components in the application. |
| `coherenceClusters` | [`[]CoherenceCluster`](#coherencecluster) | N || Coherence cluster components in the application. |
| `helidonApplications` | [`[]HelidonApplication`](#helidonapplication) | N || Helidon application components in the application. |

### WebLogicDomain

WebLogic domain components in a Verrazzano Model represent the custom resource for the WebLogic domain that is managed by the WebLogic Server Kubernetes Operator. Because the operator is what manages the domain, CR options that the model can handle are acceptable as entries in the component within the model file.

``` yaml
  weblogicDomains:
    - name: hello-weblogic
      domainCRValues:
        ...
```

| Attribute | Type | Required | Default Value | Description |
|-----------|------|----------|---------------|-------------|
| `name` | `string` | Y || Name of the component within the Verrazzano model. |
| `adminPort` | `int32` | N || External port number for the Administration console. |
| `t3Port` | `int32` | N || External port number for T3. |
| `domainCRValues` | [`[]DomainCRValue`](#domaincrvalue) | Y || Domain CR values; you can provide valid Domain CR values accepted by the WebLogic Server Kubernetes Operator with a few exceptions. |
| `connections` | [`[]Connection`](#connection) | N || List of connections used by this application component. |

### DomainCRValue

The domain CR value defines the desired state of the WebLogic domain.

{{< alert title="Limitations" color="notice" >}}

* Verrazzano uses WebLogic Server Kubernetes Operator version 3.0. Any features or values added in later versions of the operator are not valid.
* ["Domain in Image"](https://oracle.github.io/weblogic-kubernetes-operator/userguide/managing-domains/choosing-a-model/) is the only valid domain home strategy with Verrazzano in this early release. Future releases will include support for other domain home strategies.
* Domain configuration overrides are not supported in this early release of Verrazzano. If you use secrets or config maps to store configuration overrides, those overrides will not be applied and may cause other errors.
* JRF domains are not supported in this early release of Verrazzano. Restricted JRF is supported.
* Use of Oracle Platform Security Services is not supported in this early release.

{{< /alert >}}


 For a full list of valid CR values, see the WebLogic Server Kubernetes Operator repository at [https://github.com/oracle/weblogic-kubernetes-operator/blob/master/docs/domains/Domain.md](https://github.com/oracle/weblogic-kubernetes-operator/blob/master/docs/domains/Domain.md).

``` yaml
  weblogicDomains:
    - name: hello-weblogic
      domainCRValues:
        domainUID: hello-weblogic
        domainHome: /u01/oracle/user_projects/domains/hello-weblogic
        image: example.registry/hello-weblogic:latest
        includeServerOutInPodLog: true
        replicas: 2
        webLogicCredentialsSecret:
          name: hello-weblogic-credentials
        imagePullSecrets:
          - name: hello-weblogic-secret
        clusters:
          - clusterName: cluster-1
        serverPod:
          env:
            - name: JAVA_OPTIONS
              value: "-Dweblogic.StdoutDebugEnabled=false"
            - name: USER_MEM_ARGS
              value: "-Djava.security.egd=file:/dev/./urandom "
            - name: WL_HOME
              value: /u01/oracle/wlserver
            - name: MW_HOME
              value: /u01/oracle
```

| Attribute | Type | Required | Default Value | Description |
|-----------|------|----------|---------------|-------------|
| `domainUID` | `string` | N | Value of `metadata.name`| Domain unique identifier. It is recommended that this value be unique to assist in future work to identify related domains in active-passive scenarios across data centers; however, it is only required that this value be unique within the namespace, similarly to the names of Kubernetes resources. This value is distinct and need not match the domain name from the WebLogic domain configuration. Defaults to the value of metadata.name. |
| `domainHome` | `string` | N | `/u01/domains/` | Path to the WebLogic domain home in the image. |
| `image` | `string` | Y || Docker image to use for pods in the WebLogic domain. |
| `logHome` | `string` | Y || The directory in a server's container in which to store the domain, Node Manager, server logs, server *.out, and optionally HTTP access log file. |
| `logHomeEnabled` | `boolean` | Y | `false` | Enables the WebLogic Server Kubernetes Operator to override the domain log location. |
| `webLogicCredentialsSecret` | [`VerrazzanoSecret`](#verrazzanosecret) | Y || Secret containing administrative credentials for the WebLogic domain. |
| `imagePullSecrets` | [`[]VerrazzanoSecret`](#verrazzanosecret) | Y || Name of the secret for pulling Docker images for the WebLogic domain. |
| `clusters` | [`[]WebLogicCluster`](#weblogiccluster) | Y ||List of clusters for which additional configuration is needed. |

### VerrazzanoSecret

VerrazzanoSecret identifies a Kubernetes secret by name

| Attribute | Type | Required | Default Value | Description |
|-----------|------|----------|---------------|-------------|
| `name` | `string` | Y || The name of the secret. |

### WebLogicCluster

Optional list of clusters for which additional configuration is needed.

| Attribute | Type | Required | Default Value | Description |
|-----------|------|----------|---------------|-------------|
| `clusterName` | `string` | Y || The name of the cluster. This value must match the name of a WebLogic cluster already defined in the WebLogic domain configuration. |
| `serverStartState` | `string` | RUNNING || Desired start state for managed servers in the cluster: ADMIN or RUNNING (default) |
| `serverPod` | [`PodSpec`](https://v1-16.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.16/#podspec-v1-core)


### CoherenceCluster


## Coherence Cluster Components
Note that support for Coherence is an experimental feature in this release of Verrazzano.

Verrazzano relies on version 2.1.1 of the [Coherence Operator](https://github.com/oracle/coherence-operator).  For the Coherence clusters section of the Verrazzano Model, Coherence custom resource values are defined in Verrazzano and then converted to a custom resource that the Coherence Operator can interpret.

A Coherence cluster component must have the following item:

* name

Coherence cluster components typically have the following items:

* image
* imagePullSecrets
* cacheConfig
* pofConfig


| Attribute | Type | Required | Default Value | Description |
|-----------|------|----------|---------------|-------------|
| `name` | `string` | Y || Name of the component within the Verrazzano model. |
| `image` | `string` | N || The name of the image. More info: https://kubernetes.io/docs/concepts/containers/images |
| `imagePullSecrets` | [`[]VerrazzanoSecret`](#verrazzanosecret) | N || ImagePullSecrets is an optional list of references to secrets in the same namespace to use for pulling any of the images used by this PodSpec. If specified, these secrets will be passed to individual puller implementations for them to use. For example, in the case of docker, only DockerConfig type secrets are honored. More info: https://kubernetes.io/docs/concepts/containers/images#specifying-imagepullsecrets-on-a-pod |
| `cacheConfig` | `string` | N || CacheConfig is the name of the cache configuration file to use see: [Configure Cache Config File](https://oracle.github.io/coherence-operator/docs/3.0.2/#/about/04_coherence_spec#coherence_settings/030_cache_config.adoc) |
| `connections` | [`[]Connection`](#connection) | N || List of connections used by this application component. |
      

### HelidonApplication

Helidon applications must have the following items defined in the model file:
* name
* image
* imagePullSecrets

Helidon applications typically have connections defined as part of the components specification, including REST, database, Coherence, and ingress connections as described for the previous component types.

Helidon applications are managed by the Verrazzano Helidon App Operator. See the source for the operator for the list of additional configuration properties available for Helidon applications.

| Attribute | Type | Required | Default Value | Description |
|-----------|------|----------|---------------|-------------|
| `name` | `string` | Y || Name of the component within the Verrazzano model. |
| `image` | `string` | Y || Container image that runs the application. Must be a path-like or URI-like representation of an OCI image. May be prefixed with a registry address and should be suffixed with a tag.. |
| `imagePullSecret` | `string` | N || Specifies the name of a Kubernetes Secret from which the credentials required to pull this container's image can be loaded. |
| `connections` | [`[]Connection`(#connection)] | N || List of connections used by this application component. |

### Connection

The connection defines an ingress or egress network connection needed by an application component.

| Attribute | Type | Required | Default Value | Description |
|-----------|------|----------|---------------|-------------|
| `rest` | [`RESTConnection`](#restconnection) | N || Connections of type REST needed by the application. |
| `ingress` | [`[]IngressConnection`](#ingressconnection) | N || The names of the ingresses to associate with this component. |


### RESTConnection

You can define a REST connection from one component in the model to another component in the same model. When you define a REST connection between components, you can then define variable names that will be provided in the Verrazzano Binding. Verrazzano also sets up network policies that enable the components to communicate in the service mesh over TLS.

Settings:

* Target: The name of the target component within the same model.
* EnvironmentVariableForHost: The DNS name or IP address of the target component (its Kubernetes service).
* EnvironmentVariableForPort: The port for the target component.

| Attribute | Type | Required | Default Value | Description |
|-----------|------|----------|---------------|-------------|
| `target` | `string` | Y || Name of the target component in the Verrazzano application.
| `environmentVariableForHost` | `string` | N || Name of the environment variable that contains the DNS name of the Kubernetes service in target component. |
| `environmentVariableForPort` | `int32` | N || Name of the environment variable that contains the port number for the service in target component. |

### IngressConnection

The Ingress connection defines an ingress associated with an application component.

| Attribute | Type | Required | Default Value | Description |
|-----------|------|----------|---------------|-------------|
| `name` | `string` | Y || Name of the ingress to connect to the application. Ingress details are defined in the binding.
| `match` | `[]IngressConnectionMatch` | N || Match rules associated with the ingress connection. |


### CoherenceConnections
You can define a Coherence connection for a component that needs to communicate with a Coherence cluster. The Coherence cluster must also be defined in the same Verrazzano Model.

Settings:

* Target: The name of the target Coherence component.
* Address: The Coherence cluster services address.

### DatabaseConnection

In the Verrazzano Model, you can define connections to external databases. These connections then become available to modify in the Verrazzano Binding. That is, you can identify a necessary database connection in the model, and then define credentials and the URL for the database in the binding. Verrazzano operators then handle the database connection accordingly.

* Target: name of the database to specify in a Verrazzano Binding. That is, in the binding, you will define a database entry that the component will connect to.
* DatasourceName: The name of the data source within the WebLogic configuration that will map to the connected database.


### IngressConnectionMatch

The Match rule associated with the ingress connection.

| Attribute | Type | Required | Default Value | Description |
|-----------|------|----------|---------------|-------------|
| `uri` | `string` | Y || Name of the ingress to connect to the application. Ingress details are defined in the binding.


## Additional Info

See the following additional documentation:

* WebLogic Server Kubernetes Operator Reference: [https://oracle.github.io/weblogic-kubernetes-operator/userguide/managing-domains/domain-resource/#domain-resource-spec-elements](https://oracle.github.io/weblogic-kubernetes-operator/userguide/managing-domains/domain-resource/#domain-resource-spec-elements)
* Coherence Operator Reference: [https://oracle.github.io/coherence-operator/docs/2.1.1/#/clusters/010_introduction](https://oracle.github.io/coherence-operator/docs/2.1.1/#/clusters/010_introduction)
