---
title: "Verrazzano Application Binding"
weight: 2
bookCollapseSection: true
---

# The Verrazzano Application Binding


{{< hint danger >}}
** Important ** The details on this page are subject to change.
{{< /hint >}}

The Verrazzano Application Binding (vb Kubernetes object type) maps a Verrazzano Application Model to an environment. The binding defines placement of the components, environment-specific aspects of a component, and connection details for the connections defined in the model.

Adding a binding to the Verrazzano instance results in a running application: Namespaces are created in the specified clusters, components are deployed in those namespaces, and ingresses, network policies, and routing rules are created in the service mesh. Behind the scenes, Verrazzano also copies secrets where necessary, creates custom resources, and deploys operators for the various component types in the application model.

There can be zero to many bindings to every model; a binding can refer to one model only.

### VerrazzanoApplicationBinding

This CRD is used to describe a "binding".  A binding provides environment and instance-specific
information about an application, for example, information that would be different in each
deployment/instance.  A good example would be credentials and URLs used to connect to a
database.  Bindings refer to (and extend) "models" (see below).

```
kind: VerrazzanoBinding
metadata:
  name:                        Name of the binding
  namespace:                   Namespace for the binding
spec:
    description                Description of the binding
    modelName                  Reference to a Verrazzano application model
    []-weblogicBindings
        name                   Name of the component to bind, as defined in the model
        replicas               Initial number of managed server instances to run
    []-coherenceBindings
        name                   Name of the component to bind, as defined in the model
        -replicas              Initial number of members of the Coherence cluster
    []-helidonBindings
        name                   Name of the component to bind, as defined in the model
        -replicas              Initial number of replicas for a Helidon application
    []-databaseBindings
        name                   Name of the database component in the model, or of the target in a database connection definition in the model
        credentials            Name of the Kubernetes secret that contains the database credentials
        url                    Database connect string (JDBC URL)
    []-ingressBindings
        name                   Name of the ingress connection as defined in the model
        dnsName                DNS name for the ingress
    []-placement               List of "placements" of model components
        name                   Name of the Kubernetes cluster as defined in the Verrazzano environment
        []namespaces           
            name               Name of the namespace in which to place the components
            []components       List of components to place in the namespace on that cluster
                name           

```

Note: A hyphen prefix denotes an optional element.

Here is an example of a `VerrazzanoApplicationBinding`:

```yaml
apiVersion: verrazzano.io/v1beta1
kind: VerrazzanoBinding
metadata:
  name: bobs-books-binding
  namespace: default
spec:
  description: "Bob's Books binding"
  modelName: bobs-books-model
  coherenceBindings:
    - name: "bobbys-coherence"
      replicas: 3
    - name: "roberts-coherence"
      replicas: 2
  helidonBindings:
    - name: "roberts-helidon-stock-application"
      replicas: 2
    - name: "bobbys-helidon-stock-application"
      replicas: 3
  weblogicBindings:
    - name: "bobbys-front-end"
      replicas: 1
    - name: "bobs-bookstore"
      replicas: 1
  databaseBindings:
    - name: mysql
      credentials: mysql-credentials
      url: "jdbc:mysql://mysql.bob.svc.default.local:3306/books"
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
  ingressBindings:
    - name: "bobbys-ingress"
      dnsName: "*"
    - name: "bobs-ingress"
      dnsName: "*"
    - name: "roberts-ingress"
      dnsName: "*"
```
### Database Bindings
The Verrazzano Model allows you to define connections to external databases.  You can then set the credentials and the URL for the database in the Verrazzano binding.  The database binding has the following fields:

* Name: The name of the database binding. A database connection in the model is linked by its `target` field to the database binding `name`.
* Credentials: The credentials to be used to connect to the database.
* URL: The URL for the database connection.

If a WebLogic component specifies a database connection that has a corresponding `databaseBinding` then the Verrazzano operators will:

1. Copy the secret specified in the `databaseBinding` to the namespace of the WebLogic domain.
2. Create a config map in the namespace of the WebLogic domain to specify overrides for the URL and secret.  These configuration overrides (also called situational configuration) are used to customize the database configuration for the WebLogic domain.
3. Specify the override config map when the WebLogic domain is created.

For example, if a `weblogicDomain` in the model has a database connection...

```   
connections:
    - database:
      - target: mysql
       datasourceName: books
```
and the binding has a database binding...
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
A config map for override values will be created in the WebLogic domain namespace with values from the secret.

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
