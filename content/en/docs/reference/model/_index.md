---
title: "Verrazzano Application Model"
weight: 1
bookCollapseSection: true
---

The Verrazzano Application Model (`vm` kubectl resource) is a Kubernetes Custom Resource Definition (CRD) that is added to the Verrazzano management cluster. This CRD describes a "Verrazzano Application," which is made up of one or more components.  Components can be WebLogic domains, Coherence clusters, Helidon microservices, or other generic container workloads.  The model also defines connections between components, ingresses to an application, and connections to external services, such as a database or a REST endpoint. Conceptually, the model captures information about the application which does not vary based on where the application is deployed.  Then a Verrazzano Application Binding (`vb` kubectl resource) is used to map the Verrazzano Application defined in the model to the deployment environment. For example, the WebLogic domain X always talks to database Y, no matter how many times this application is deployed. In a particular instance or deployment of the application, for example, the "test" instance, there may be different credentials and a different URL to access the test version of Y database, but X always talks to Y. The application ***model*** must define a connection to the database, but the actual credentials and URL used when the application is deployed is defined in the ***binding***. Bindings map the application to the environment.

The combination of a model and binding produces an instance of an application.
Both the model and binding are meant to be sparse; they contain only the information that is needed to deploy the application.  Anything that Verrazzano can infer or use a default value for, can be omitted from these files.

For an example Verrazzano Application Model, see [demo-model](https://github.com/verrazzano/verrazzano/blob/master/examples/bobs-books/bobs-books-model.yaml).

### Top-Level Attributes

The top-level attributes of a Verrazzano Application Model define its `version`, `kind`, `metadata`, and `spec`.

``` yaml
apiVersion: verrazzano.io/v1beta1
kind: VerrazzanoModel
metadata:
  name: hello-world-model
  namespace: default
spec:
  ...
```

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `apiVersion` | `String` | Y | A string that identifies the version of the schema the object should have. Must be `verrazzano.io/v1beta1`. |
| `kind` | `String` | Y | Must be `VerrazzanoModel`. |
| `metadata` | [`ObjectMeta`](https://v1-16.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.16/#objectmeta-v1-meta) | Y | Information about the model. |
| `spec`| [`Spec`](#spec) | Y | A specification for application model attributes. |

### Spec

The specification defines a Verrazzano Application Model.

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
  genericComponents:
    - name: hello-generic
      ...
```

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `description` | `String` | Y | Description of the model. |
| `weblogicDomains` | [`WebLogicDomain`](#weblogicdomain) | N | WebLogic Server domain components in the application. |
| `coherenceClusters` | [`CoherenceCluster`](#coherencecluster) | N | Coherence cluster components in the application. |
| `helidonApplications` | [`HelidonApplication`](#helidonapplication) | N | Helidon application components in the application. |
| `genericComponents` | [`GenericComponent`](#genericcomponent) | N | Generic components in the application. |

### WebLogicDomain

WebLogic domain components in a Verrazzano Application Model represent the custom resource for the WebLogic domain that is managed by the WebLogic Server Kubernetes Operator. Because the operator is what manages the domain, custom resource options that the model can handle are acceptable as entries in the component within the model file.

``` yaml
  weblogicDomains:
    - name: hello-weblogic
      domainCRValues:
        ...
```

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | `String` | Y | Name of the component within the Verrazzano Application Model. |
| `domainCRValues` | [`DomainCRValue`](#domaincrvalue) | Y | Domain Custom Resource (CR) values; provide valid domain CR values accepted by the WebLogic Server Kubernetes Operator. |
| `adminPort` | `Integer` | N | External port number for the WebLogic Server Administration Console. |
| `connections` | [`Connection`](#connection) | N | List of connections used by this application component. |
| `t3Port` | `Integer` | N | External port number for T3. |

### DomainCRValue

The domain CR value defines the desired state of the WebLogic domain.

{{< alert title="Limitations" color="notice" >}}

In this early release of Verrazzano:

* Verrazzano uses WebLogic Server Kubernetes Operator version 3.0.2. Any features or values added in later versions of the operator are not valid.
* ["Model in Image"](https://oracle.github.io/weblogic-kubernetes-operator/userguide/managing-domains/choosing-a-model/) is the only valid domain home source type that can be used.
* Domain configuration overrides are not supported. If you use secrets or config maps to store configuration overrides, those overrides will not be applied and may cause other errors.
* JRF domains are not supported. Restricted JRF _is_ supported.
* Use of Oracle Platform Security Services is not supported.

{{< /alert >}}


 For a full list of valid domain CR values, see [https://github.com/oracle/weblogic-kubernetes-operator/blob/master/docs/domains/Domain.md](https://github.com/oracle/weblogic-kubernetes-operator/blob/master/docs/domains/Domain.md).

``` yaml
  weblogicDomains:
    - name: hello-weblogic
      domainCRValues:
        domainUID: hello-weblogic
        domainHome: /u01/oracle/user_projects/domains/hello-weblogic
        image: example.registry/hello-weblogic:latest
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
| `domainUID` | `String` | N | Value of `metadata.name`| Domain unique identifier. It is recommended that this value be unique to assist in future work to identify related domains in active-passive scenarios across data centers; however, it is only required that this value be unique within the namespace, similarly to the names of Kubernetes resources. This value is distinct and need not match the domain name from the WebLogic domain configuration. Defaults to the value of `metadata.name`. |
| `domainHome` | `String` | N | `/u01/domains/` | Path to the WebLogic domain home in the image. |
| `image` | `String` | Y | | Docker image to use for pods in the WebLogic domain. |
| `replicas` | `Integer` | Y | 1 | Default number of cluster member Managed Server instances to start for each WebLogic cluster in the domain configuration.
| `webLogicCredentialsSecret` | [`VerrazzanoSecret`](#verrazzanosecret) | Y | | Secret containing administrative credentials for the WebLogic domain. |
| `imagePullSecrets` | [`VerrazzanoSecret`](#verrazzanosecret) | Y | | Name of the secret for pulling Docker images for the WebLogic domain. |
| `clusters` | `Cluster` | N | | List of clusters for which additional configuration is needed. For more information, see [https://github.com/oracle/weblogic-kubernetes-operator/blob/master/docs/domains/Domain.md](https://github.com/oracle/weblogic-kubernetes-operator/blob/master/docs/domains/Domain.md).|
| `serverPod` | [`ServerPod`](https://v1-16.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.16/#podspec-v1-core) | N | | Desired behavior of a pod for a WebLogic Server.|

### VerrazzanoSecret

VerrazzanoSecret identifies a Kubernetes secret by name.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | `String` | Y | The name of the secret. |


### CoherenceCluster

Verrazzano relies on version 2.1.1 of the [Coherence Operator](https://github.com/oracle/coherence-operator).  For the Coherence clusters section of the Verrazzano Application Model, Coherence custom resource values are defined in Verrazzano and then converted to a custom resource that the Coherence Operator can interpret.

A Coherence cluster component must have the following item:

* `name`
* `image`
* `cacheConfig`
* `pofConfig`


| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `cacheConfig` | `String` | Y| Name of the cache configuration file to use. |
| `connections` | [`Connection`](#connection) | N | List of connections used by this application component. |
| `image` | `String` | Y | The name of the image. For more information, see https://kubernetes.io/docs/concepts/containers/images |
| `imagePullSecrets` | [`VerrazzanoSecret`](#verrazzanosecret) | N | List of Kubernetes secrets from which the credentials required to pull this container's image can be loaded. |
| `name` | `String` | Y | Name of the component within the Verrazzano Application Model. |
| `pofConfig` | `String` | Y | Name of the Portable Object Format (POF) configuration file to use. |
| `ports` | [`NamedPortSpec`](https://oracle.github.io/coherence-operator/docs/3.0.2/#/about/04_coherence_spec#_namedportspec) | N | Defines a named port for a Coherence cluster component. |


### HelidonApplication

Helidon applications must have the following items defined in the model file:
* `name`
* `image`

Helidon applications typically have connections defined as part of the components specification, including REST, database, Coherence, and ingress connections.

Helidon applications are managed by the Verrazzano Helidon Application Operator.

| Attribute | Type | Required | Default Value |Description |
|-----------|------|----------|---------------|-------------|
| `connections` | [`Connection`](#connection) | N | | List of connections used by this application component. |
| `env` | [`EnvVar`](https://v1-16.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.16/#envvar-v1-core) | N | | List of environment variables to set for container. |
| `fluentdEnabled` | `Boolean` | N | `true` | Determines whether a Fluentd container is included for sending logs to Elasticsearch. |
| `image` | `String` | Y | | Container image that runs the application. Must be a path-like or URI-like representation of an OCI image. May be prefixed with a registry address and should be suffixed with a tag. |
| `imagePullSecrets` | [`VerrazzanoSecret`](#verrazzanosecret) | N | | List of Kubernetes secrets from which the credentials required to pull this container's image can be loaded. |
| `name` | `String` | Y | | Name of the component within the Verrazzano Application Model. |
| `port` | `Integer` | N | `8080` | Port to be used for the service port. |
| `targetPort` | `Integer` | N | `8080` | Target port to be used for the service target port. |


### GenericComponent

Generic components must have the following items defined in the model file:
* `name`
* `deployment`

Generic components are managed by the Verrazzano Operator and result in a single Kubernetes deployment and service being created.

Generic components typically have connections defined as part of the components specification, including REST and ingress connections.

``` yaml
  genericComponents:
    - name: "verrazzano-generic"
      replicas: 2
      fluentdEnabled: true
      deployment:
        containers:
          - image: generic-verrazzano:0.0.1
            name: verrazzano-generic
            ports:
              - containerPort: 8080
                name: generic-port
      connections:
        - ingress:
            - name: "generic-ingress"
              match:
                - uri:
                    prefix: /
```

| Attribute | Type | Required | Default Value | Description |
|-----------|------|----------|---------------|-------------|
| `name` | `String` | Y | | Name of the component within the Verrazzano Application Model. |
| `replicas` | `Integer` | N | `1` | Number of desired pods for a generic component. |
| `fluentdEnabled` | `Boolean` | N | `true` | Determines whether a Fluentd container is included for sending logs to Elasticsearch. |
| `deployment` | [`PodSpec`](https://v1-16.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.16/#podspec-v1-core) | Y | | Desired behavior of a pod for a generic component. |
| `connections` | [`Connection`](#connection) | N | | List of connections used by this application component. |

### Connection

Connection defines network connections and/or database connections needed by an application component.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `coherence` | [`CoherenceConnection`](#coherenceconnection) | N | Coherence type connections needed by a component. |
| `database` | [`DatabaseConnection`](#databaseconnection) | N | Database type connections needed by a component. |
| `ingress` | [`IngressConnection`](#ingressconnection) | N | Ingresses to associate with a component. |
| `rest` | [`RESTConnection`](#restconnection) | N | REST type connections needed by a component. |


### CoherenceConnection
You can define a Coherence connection for a component that needs to communicate with a Coherence cluster. The Coherence cluster must also be defined in the same Verrazzano Application Model.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | `String` | Y | Name of the target Coherence component. |
| `address` | `String` | Y | Coherence cluster services address. |

### DatabaseConnection

In the Verrazzano Application Model, you can define connections to external databases. These connections then become available to modify in the Verrazzano Application Binding.
That is, you can identify a necessary database connection in the model, and then define credentials and the URL for the database in the binding. Verrazzano operators then handle the database connection accordingly.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | `String` | Y | Name of the database to specify in a Verrazzano Application Binding. That is, in the binding, you will define a database entry to which the component will connect. |
| `datasourceName` | `String` | Y | Name of the data source within the WebLogic configuration that will map to the connected database. |

### IngressConnection

The Ingress connection defines an ingress associated with an application component.

| Attribute | Type | Required | Default Value | Description |
|-----------|------|----------|---------------|-------------|
| `name` | `String` | Y | | Name of the ingress to connect to the application. Ingress details are defined in the binding. |
| `match` | [`IngressConnectionMatch`](#ingressconnectionmatch) | N | `prefix "/"` | Match rules associated with the ingress connection. |


### RESTConnection

You can define a REST connection from one component in the model to another component in the same model.
When you define a REST connection between components, you can then define variable names that will be provided in the
Verrazzano Application Binding. Verrazzano also sets up network policies that enable the components to communicate in the service mesh over TLS.

| Attribute | Type | Required | Description |
|-----------|------|--------- |-------------|
| `target` | `String` | Y | Name of the target component in the Verrazzano application. |
| `environmentVariableForHost` | `String` | Y | Name of the environment variable that contains the DNS name of the Kubernetes service in the target component. |
| `environmentVariableForPort` | `Integer` | Y | Name of the environment variable that contains the port number for the service in the target component. |


### IngressConnectionMatch

The match rule associated with the ingress connection.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `uri` | [`StringMatch`](#stringmatch) | Y | Describes how to match a given string in HTTP headers. Match is case-sensitive. |


### StringMatch

Describes how to match a given string in HTTP headers. Match is case-sensitive.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `exact` | `String` `(oneOf)` | N | Exact string match. |
| `prefix` | `String` `(oneOf)` | N | Prefix string match. |
| `regex` | `String` `(oneOf)` | N | RE2 style regex-based match. |

## Additional Information

See the following documentation:

* WebLogic Server Kubernetes Operator Reference: [https://oracle.github.io/weblogic-kubernetes-operator/userguide/managing-domains/domain-resource/#domain-resource-spec-elements](https://oracle.github.io/weblogic-kubernetes-operator/userguide/managing-domains/domain-resource/#domain-resource-spec-elements)
* Coherence Operator Reference: [https://oracle.github.io/coherence-operator/docs/2.1.1/#/clusters/010_introduction](https://oracle.github.io/coherence-operator/docs/2.1.1/#/clusters/010_introduction)
