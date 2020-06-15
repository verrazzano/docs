---
title: "Verrazzano Application Binding"
weight: 2
bookCollapseSection: true
---

# The Verrazzano Application Binding 


{{< hint danger >}}
** Important ** The details on this page are still subject to change.
{{< /hint >}}

The Verrazzano Application Binding (vb) maps a Verrazzano Application Model to an environment. The binding defines placement of the components, environment-specific aspects of each component (such as volume mounts), and connection details for the connections defined in the model.

Adding a binding to the Verrazzano instance results in a running application: Namespaces are created in the specified clusters, components are deployed in those namespaces, and ingresses, netowrik policies, and routing rules are created in the service mesh. 

There can be zero to many bindings to every model, and a binding can refer to one model only.

### VerrazzanoApplicationBinding

This CRD is used to describe a "binding".  A binding provides environment/instance-specific
information about an application, i.e. information that would be different in each 
deployment/instance.  A good example would be credentials and URLs used to connect to a 
database.  Bindings refer to (and extend) "models" (see below).

```
VerrazzanoApplicationBinding
    name                       the name of the binding
    version                    the version of the binding
    descripiton                a description of the binding
    model                      a reference to a TibubronApplicationModel
        name                   the name of the model file this binding refers to
        version                the version of the model file this binding refers to
    []-placement               a list of "placements" of model components
        name                   the name of the k8s cluster 
        []namespaces           a list of k8s namespaces in that cluster
            name               the name of the namespace
            []components       a list of components to place in that namespace on that cluster
                name           the name of each component to place in the specified namespace
    []-weblogicBindings
        name                   the name of the component to bind, as defined in the model
        replicas               number of managed server instances to run
    []-coherenceBindings
        name                   the name of the component to bind, as defined in the model
        -clusterSize
        -serviceAccountName    may go away
        -store
            -logging
                -level
                -configFile
                -configMapName
        -maxHeap
        -jvmArgs
        -javaOpts
        -wkaRelease
        -wka
        -ports
        -env
        -annotations
        -labels
        -persistence
            -size
            -volume
        -snapshot
            -size
            -volume
        -jmx
            -enabled
            -replicas
            -maxHeap                            model or binding???
        -readinessProbe
            -initialDelaySeconds
            -periodSeconds
            -timeoutSeconds
            -successThreshold
            -failureThreshold
    []-databaseBindings
        name                   the name of the binding
        credentials            (type=database only) the name of the secret containing the database credentials
        url                    (type=database only) the database connect string (jdbc url) 
    []-atpBindings
        name                    the name of the binding, and also db name and display name for the ATP instance
        compartmentId           the OCID of the compartment in which the ATP DB exists or is to be provisioned
        -cpuCount               the number of ATP CPUs. default = 1
        -storageSizeTBs         the ATP storage size. default = 1
        -licenseType            the ATP license type (NEW or BYOL). default = BYOL
        -walletSecret           the name of the secret that contains/will contain the ATP wallet, default = name with "-wallet" appended
        -walletPassphraseSecret the name of the secret that contains/will contain the passphrase for the ATP wallet. default = name with "-passphrase" appended    
    []-ingressBindings
        name                   the name of the binding
        port                   the TCP/IP port number
        dnsName                the DNS name for the ingress
        -prefix                the prefix for the ingress. default = "/"
    []-helidonBindings
        name                   the name of the binding
        -replicas              the number of replicas for a Helidon application
 
```

Note: A hyphen prefix denotes an optional element.

Here is an example of a `VerrazzanoApplicationBinding`:

```yaml
name: "Bob's Books Test Environment"
description: "The test environment for Bob's Books"
version: "1.0"
model:
  name: "Bob's Books"
  version: "1.0"
weblogicBindings:
    Name:      "bobbys-front-end"
    Replicas:  1
    Name:      "bobs-bookstore"
    Replicas:  1
coherenceBindings:
  - name: "bobbys-coherence"
    cacheConfig: "bobbys-cache-config.xml"
    pofConfig: "bobbys-pof-config.xml"
databaseBindings:
  - name: "books"
    credentials: "booksdb-secret"
    url: "jdbc:mysql://mysql:3306/books"
atpBindings:
  - name: "books-atp"
    compartmentId: "COMPARTMENT_OCID"
    cpuCount: 1
    storageSizeTBs: 1
    licenseType: BYOL
    walletSecret: books-atp-wallet
    walletPassphraseSecret: books-atp-passphrase      
ingressBindings:
  - name: "roberts-ingress"
    port: "80"
    dnsName: "roberts-books.weblogick8s.org"
  - name: "bobbys-ingress"
    port: "31380"
    dnsName: "bobbys-books.weblogick8s.org"
helidonBindings:
  - name: bobbys-helidon-stock-application
    replicas: 1
placement: 
  - name: "cloud"
    namespaces:
      - name: "robert"
        components:
          - name: "roberts-helidon-stock-application"
          - name: "roberts-coherence"
  - name: "onprem"
    namespaces:
      - name: "bobby"
        components:
          - name: "bobbys-front-end"
          - name: "bobbys-helidon-stock-application"
          - name: "bobbys-coherence"
      - name: "bob"
        components:
          - name: "bobs-bookstore"
```
