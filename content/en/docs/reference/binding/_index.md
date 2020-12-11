---
title: "Verrazzano Application Binding"
weight: 2
bookCollapseSection: true
---

The Verrazzano Application Binding (`vb` Kubernetes object type) maps a Verrazzano Application Model to an environment. The binding defines placement of the components, environment-specific aspects of a component, and connection details for the connections defined in the model.

Adding a binding to the Verrazzano instance results in a running application: namespaces are created in the specified clusters, components are deployed in those namespaces, and ingresses, network policies, and routing rules are created in the service mesh. Behind the scenes, Verrazzano also copies secrets where necessary, creates custom resources, and deploys operators for the various component types in the application model.

There can be zero to many bindings to every model; a binding can refer to one model only.

### VerrazzanoApplicationBinding

This CRD is used to describe a _binding_.  A binding provides environment and instance-specific
information about an application, for example, information that would be different in each
deployment/instance.  A good example would be credentials and URLs used to connect to a
database.  Bindings refer to (and extend) _models_ (for an example, see [Database Bindings](#database-bindings)).

### Top-Level Attributes

The top-level attributes of a Verrazzano Application Binding define its `version`, `kind`, `metadata`, and `spec`.

```yaml
apiVersion: verrazzano.io/v1beta1
kind: VerrazzanoBinding
metadata:
  name: bobs-books-binding
  namespace: default
spec:
  ...
```  

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `apiVersion` | `String` | Y | A string that identifies the version of the schema that the object should have. Must be `verrazzano.io/v1beta1`. |
| `kind` | `String` | Y | Must be `VerrazzanoBinding`. |
| `metadata` | [`ObjectMeta`](https://v1-16.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.16/#objectmeta-v1-meta) | Y | Information about the binding. |
| `spec`| [`Spec`](#spec) | Y | A specification for application binding attributes. |

### Spec

The specification defines a Verrazzano Application Binding.


``` yaml
spec:
    description: "Bob's Books binding"                
    modelName: bobs-books-model
    coherenceBindings:
      - name: "bobbys-coherence"
        ...
    helidonBindings:
      - name: "roberts-helidon-stock-application"
        ...
    weblogicBindings:
      - name: "bobbys-front-end"
        ...
    databaseBindings:
      - name: mysql
        ...
    placement:
      - name: local
        ...
    ingressBindings:
      - name: "bobbys-ingress"                
        ...          
```

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `description` | `String` | Y | Description of the binding. |
| `modelName` | `String` | Y | Reference to a Verrazzano Application Model. |
| `coherenceBindings` | [`CoherenceBinding`](#coherencebinding) | N | Coherence components to bind, as defined in the model. |
| `helidonBindings` | [`HelidonBinding`](#helidonbinding) | N | Helidon application components to bind, as defined in the model. |
| `weblogicBindings` | [`WebLogicBinding`](#weblogicbinding) | N | WebLogic components to bind, as defined in the model. |
| `databaseBindings` | [`DatabaseBinding`](#databasebinding) | N | Database component in the model, or the target in a database connection definition in the model, to bind. |
| `placement` | [`Placement`](#placement) | N | List of "placements" of model components. |
| `ingressBindings` | [`IngressBinding`](#ingressbinding) | N | Ingresses to bind, as defined in the model. |


#### CoherenceBinding

```yaml
coherenceBindings:
  - name: "bobbys-coherence"
    replicas: 3
  - name: "roberts-coherence"
    replicas: 2
```   

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | `String` | N | Name of the Coherence component. |
| `replicas` | `Integer` | N | Initial number of members of the Coherence cluster. |


#### HelidonBinding

```yaml
helidonBindings:
  - name: "roberts-helidon-stock-application"
    replicas: 2
  - name: "bobbys-helidon-stock-application"
    replicas: 3
```

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | `String` | N | Name of the Helidon component. |
| `replicas` | `Integer` | N | Initial number of replicas for a Helidon application. |

#### WebLogicBinding

```yaml
weblogicBindings:
  - name: "bobbys-front-end"
    replicas: 1
  - name: "bobs-bookstore"
    replicas: 1
```

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | `String` | N | Name of the WebLogic component. |
| `replicas` | `Integer` | N | Initial number of Managed Server instances to run. |

#### DatabaseBinding

```yaml
databaseBindings:
  - name: mysql
    credentials: mysql-credentials
    url: "jdbc:mysql://mysql.bob.svc.default.local:3306/books"
```

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | `String` | N | Name of the database component in the model, or of the target in a database connection definition, in the model. |
| `credentials` | `String` | N | Name of the Kubernetes secret that contains the database credentials. |
| `url` | `String` | N | Database connect string (JDBC URL). |

#### Placement

```yaml
placement:
  - name: local
    namespaces:
      - name: bobby
        components:
          - name: bobbys-coherence
          - name: bobbys-front-end
          - name: bobbys-helidon-stock-application
      - name: robert
        components:
          - name: roberts-helidon-stock-application
          - name: roberts-coherence
      - name: bob
        components:
          - name: bobs-bookstore
```

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | `String` | N | Name of the Kubernetes cluster as defined in the Verrazzano environment. |
| `namespaces` | [`Namespaces`](#namespaces) | N | Namespaces defined in the Verrazzano environment. |

##### Namespaces


| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | `String` | N | Name of the namespace in which to place the components. |
| `components` | `String` | N | List of components to place in the namespace on that cluster. |



#### IngressBinding

```yaml
ingressBindings:
  - name: "bobbys-ingress"
    dnsName: "*"
  - name: "bobs-ingress"
    dnsName: "*"
  - name: "roberts-ingress"
    dnsName: "*"

```


| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | `String` | N | Name of the ingress connection as defined in the model. |
| `dnsName` | `String` | N | DNS name for the ingress. |




### Database Bindings

The Verrazzano Application Model lets you define connections to external databases.  You can then set the credentials and the URL for the database in the Verrazzano Application Binding.  The database binding has the following fields:

* `name`: The name of the database binding. A database connection in the model is linked by its `target` field to the database binding `name`.
* `credentials`: The credentials to be used to connect to the database.
* `url`: The URL for the database connection.

If a WebLogic component specifies a database connection that has a corresponding `databaseBinding`, then the Verrazzano operators will:

1. Copy the secret specified in the `databaseBinding` to the namespace of the WebLogic domain.
2. Create a ConfigMap in the namespace of the WebLogic domain to specify overrides for the URL and secret.  These configuration overrides (also called situational configuration) are used to customize the database configuration for the WebLogic domain.
3. Specify the override ConfigMap when the WebLogic domain is created.

For example, if a `weblogicDomain` in the model has a database connection, as follows:

```   
connections:
    - database:
      - target: mysql
       datasourceName: books
```
And the binding has a database binding, as follows:
```
 databaseBindings:
  - credentials: mysqlsecret
   name: mysql
   url: jdbc:mysql://mysql.default.svc.cluster.local:3306/books
```
Then the secret `mysqlsecret` will be copied from the default namespace to the namespace specified in the binding placement for the WebLogic domain. The URL will be added to the secret with the value from the database binding.  Note that the secret specified in the binding must exist in the default namespace before the model and binding are applied.

```
apiVersion: v1
data:
  password: xxxxxxxxx
  url: amRiYzpteXNxbDovL215c3FsLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWw6MzMwNi9ib29rcw==
  username: xxxxxxxx
kind: Secret
metadata:
  labels:
    weblogic.domainUID: bobs-bookstore
  name: mysqlsecret
  namespace: bob
type: Opaque
```
A ConfigMap for override values will be created in the WebLogic domain namespace with values from the secret.

```
apiVersion: v1
data:
  jdbc-books.xml: |
  <?xml version='1.0' encoding='UTF-8'?>
  <jdbc-data-source xmlns="http://xmlns.oracle.com/weblogic/jdbc-data-source"
                    xmlns:f="http://xmlns.oracle.com/weblogic/jdbc-data-source-fragment"
                    xmlns:s="http://xmlns.oracle.com/weblogic/situational-config">
    <name>books</name>
    <jdbc-driver-params>
      <url f:combine-mode="replace">jdbc:mysql://mysql:3306/books</url>
      <properties>
         <property>
            <name>user</name>
            <value f:combine-mode="replace">${secret:mysql-credentials.username}</value>
         </property>
      </properties>
      <password-encrypted f:combine-mode="replace">${secret:mysql-credentials.password:encrypt}</password-encrypted>
    </jdbc-driver-params>
  </jdbc-data-source>
  version.txt: "2.0"
kind: ConfigMap
metadata:
  labels:
    weblogic.domainUID: bobs-bookstore
  name: jdbccm
  namespace: bob
```
The overrides and override secrets are set when the WebLogic domain is created.
```
apiVersion: weblogic.oracle/v7
kind: Domain
...
  configOverrideSecrets:
  - mysqlsecret
  configOverrides: jdbccm
```
