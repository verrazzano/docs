---
title: "Verrazzano Application Binding"
weight: 2
bookCollapseSection: true
---

# The Verrazzano Application Binding 


{{< hint danger >}}
** Important ** The details on this page are subject to change.
{{< /hint >}}

The Verrazzano Application Binding (vb) maps a Verrazzano Application Model to an environment. The binding defines placement of the components, environment-specific aspects of a component, and connection details for the connections defined in the model.

Adding a binding to the Verrazzano instance results in a running application: Namespaces are created in the specified clusters, components are deployed in those namespaces, and ingresses, network policies, and routing rules are created in the service mesh. Behind the scenes, Verrazzano also copies secrets where necessary, creates custom resources, and deploys operators for the various component types in the application model. 

There can be zero to many bindings to every model, and a binding can refer to one model only.

### VerrazzanoApplicationBinding

This CRD is used to describe a "binding".  A binding provides environment/instance-specific
information about an application, i.e. information that would be different in each 
deployment/instance.  A good example would be credentials and URLs used to connect to a 
database.  Bindings refer to (and extend) "models" (see below).

```
kind: VerrazzanoBinding
metadata:
  name:                        name of the binding 
  namespace:                   namespace for the binding
spec:
    description                a description of the binding
    modelName                  a reference to a Verrazzano application model
    []-weblogicBindings
        name                   the name of the component to bind, as defined in the model
        replicas               initial number of managed server instances to run
    []-coherenceBindings
        name                   the name of the component to bind, as defined in the model
        -replicas              initial number of members of the Coherence cluster
    []-helidonBindings
        name                   the name of the component to bind, as defined in the model
        -replicas              initial number of replicas for a Helidon application
    []-databaseBindings
        name                   the name of the database component in the model, or of the target in a database connection definition in the model
        credentials            the name of the Kubernetes secret that contains the database credentials
        url                    the database connect string (jdbc url) 
    []-ingressBindings
        name                   the name of the ingress connection as defined in the model
        dnsName                the DNS name for the ingress
    []-placement               a list of "placements" of model components
        name                   the name of the k8s cluster as defined in the Verrazzano environment
        []namespaces           
            name               the name of the namespace in which to place the components
            []components       a list of components to place in the namespace on that cluster
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
