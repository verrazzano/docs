---
title: "Verrazzano Application Model"
weight: 1
bookCollapseSection: true
---

# The Verrazzano Application Model



{{< hint danger >}}
** Important ** The details on this page are subject to change.
{{< /hint >}}


The Verrazzano Model (vm kubectl resource) is a Kubernetes Custom Resource Definition (CRD) that is added to the Verrazzano management cluster. This CRD describes a "Verrazzano Application," which is made up of one or more components.  Components can be WebLogic domains, Coherence clusters, Helidon microservices, or other generic container workloads.  The model also defines connections between components, ingresses to an application, and connections to external services, such as a database or a REST endpoint. Conceptually, the model captures information about the application which does not vary based on where the application is deployed.  A Verrazzano Binding (vb kubectl resource) is then used to map the Verrazzano Application defined in the model to the deployment environment. For example, the WebLogic domain X always talks to database Y, no matter how many times this application is deployed. In a particular instance or deployment of the application, for example, the "test" instance, there may be different credentials and a different URL to access the test version of Y database, but X always talks to Y. The application ***model*** then must define a connection to the database, but the actual credentials and URL used when the application is deployed is defined in the ***binding***. Bindings map the application to the environment.

The combination of a model and and binding produces an instance of an application.
Both the model and binding are meant to be sparse - they contain only the information that is needed to deploy the application.  Anything that Verrazzano can infer or use a default value can be omitted from these files.

## Structure of the `VerrazzanoApplicationModel`

```
VerrazzanoApplicationModel
    name                                        Name of the model
    description                                 Description of the model
    []weblogicDomains
        -name                                   Name of the component. This is the name used within the application model only.
         adminPort                              External port number for the Administration Console
         t3Port                                 External port number for T3
         domainCRValues                         Domain CR values; you can provide valid Domain CR values accepted by the WebLogic Server Kubernetes Operator, with a few exceptions.
            domainUID                           WebLogic domain name
            domainHome                          Path to the WebLogic domain home in the image
            image                               Docker image to use for pods in the WebLogic domain
            logHome                             Path to the log home for the WebLogic domain
            logHomeEnabled                      Enables the WebLogic Server Kubernetes Operator to override the domain log location
            webLogicCredentialsSecret
                name                            Secret containing administrative credentials for the WebLogic domain
            imagePullSecrets
                name                            Name of the secret for pulling Docker images for the WebLogic domain
            clusters                            Optional list of clusters for which additional configuration is needed
                clusterName                     Name of the WebLogic cluster
                serverStartState                Desired start state for managed servers in the cluster: ADMIN or RUNNING (default)
                serverPod                       Configuration affecting server pods for WebLogic Server instances in the cluster
                  env
                    - name: JAVA_OPTIONS
                      value
                    - name: USER_MEM_ARGS
                      value
                    - name: WL_HOME
                      value
                    - name: MW_HOME
                      value
                replicas: 2
        -connections                            List of connections for the WebLogic domain
           []-rest                              Connections of type REST needed by the WebLogic domain
              target                            Name of the target component
              -environmentVariableForHost       DNS name of the target component (its Kubernetes service)
              -environmentVariableForPort       Port for the target component
            []-ingress
              -name                             Name of the ingress to connect to the domain
            []-database
              target                            Name of the database component defined in the model or `databasebinding` defined in the binding
              datasourceName                    JDBC data source name within the WebLogic domain configuration for the database
            []-coherence
              target                            Name of the target Coherence cluster (defined in the model)
              address                           Coherence cluster services address
    []-coherenceClusters
        - name                                  Name of component and Coherence cluster
          image
          imagePullSecrets
          cacheConfig
          pofConfig
          []-connections                         List of connections needed by the Coherence cluster
            []-rest                              Connections of type REST needed by the Coherence cluster
               target                            Name of the target REST connection
               -environmentVariableForHost       DNS name of the target component (its Kubernetes service)
               -environmentVariableForPort       Port for the target component
            []-ingress
               -name                             Name of the ingress to connect to the cluster. Ingress details are defined in the binding using this name.
            []-database
               target                            Name of the target database component defined in the model or `databasebinding` defined in the binding
            []-coherence
              target                             Name of the target Coherence cluster (defined in the model)
              address                            Coherence cluster services address
    []-helidonApplications
        name                                     Name of the component within the Verrazzano model
        image                                    Docker image:tag that runs the application
        -imagePullSecret                         Name of Kubernetes secret containing credentials for pulling the image
        []-connections                           List of connections needed by this application component
           []-rest                               Connections of type REST needed by the application
              target                             Name of the target component
              -environmentVariableForHost        DNS name of the target component (its Kubernetes service)
              -environmentVariableForPort        Port for the target component
           []-ingress
              -name                              Name of the ingress to connect to the application. Ingress details are defined in the binding.
              -match
           []-database
              target                             Name of the target database component defined in the model or `databasebinding` defined in the binding
           []-coherence
              target                             Name of the target Coherence cluster defined in the model
              address      

```
For an example Verrazzano model, see [demo-model](https://github.com/verrazzano/examples/blob/master/bobs-books/yaml/demo-model.yaml).


See the following additional documentation:

* WebLogic Server Kubernetes Operator Reference: [https://oracle.github.io/weblogic-kubernetes-operator/userguide/managing-domains/domain-resource/#domain-resource-spec-elements](https://oracle.github.io/weblogic-kubernetes-operator/userguide/managing-domains/domain-resource/#domain-resource-spec-elements)
* Coherence Operator Reference: [https://oracle.github.io/coherence-operator/docs/2.1.1/#/clusters/010_introduction](https://oracle.github.io/coherence-operator/docs/2.1.1/#/clusters/010_introduction)

## WebLogic Domain Components
WebLogic domain components in a Verrazzano model represent the custom resource for the WebLogic domain that is managed by the WebLogic Server Kubernetes Operator. Because the operator is what manages the domain, CR options that the model can handle are acceptable as entries in the component within the model file.

{{< hint working >}}
Limitations:

* Verrazzano uses WebLogic Server Kubernetes Operator version 2.6. Any features or values added in later versions of the operator are not valid.
* "Domain Home in Image" is the only valid domain home strategy with Verrazzano in this early release. Future releases will include support for other domain home strategies.
* Domain configuration overrides are not supported in this early release of Verrazzano, but will be supported in a future release. If you use secrets or config maps to store configuration overrides, those overrides will not be applied, and may cause other errors.
* JRF domains are not supported in this early release of Verrazzano. Restricted JRF is supported.
* Use of Oracle Platform Security Services is not supported in this early release.

{{< /hint >}}

A WebLogic domain component must include the following items:

* Name
* domainCRValues
	* domainUID
	* webLogicCredentialsSecret
	* image
	* imagePullSecret


A WebLogic domain component typically includes the following items:

* adminPort
* t3Port
* Clusters
	* Server Pod (e.g., server startup parameters)
* Connections
	* Rest (outbound)
	* Ingress
	* Database
	* Coherence

 For a full list of valid CR values, see the WebLogic Server Kubernetes Operator repository at [https://github.com/oracle/weblogic-kubernetes-operator/blob/master/docs/domains/Domain.md](https://github.com/oracle/weblogic-kubernetes-operator/blob/master/docs/domains/Domain.md).


## Coherence Cluster Components
Note that support for Coherence is an experimental feature in this release of Verrazzano.

Verrazzano relies on version 2.1.1 of the [Coherence Operator](https://github.com/oracle/coherence-operator).  For the Coherence clusters section of the Verrazzano model, Coherence custom resource values are defined in Verrazzano and then converted to a custom resource that the Coherence operator can interpret.

A Coherence cluster component must have the following item:

* name

Coherence cluster components typically have the following items:

* image
* imagePullSecrets
* cacheConfig
* pofConfig


## Helidon Application Components
Helidon applications must have the following items defined in the model file:
* name
* image
* imagePullSecrets

Helidon applications typically have connections defined as part of the components specification, including REST, database, Coherence, and ingress connections as described for the previous component types.

Helidon applications are managed by the Verrazzano Helidon App Operator. See the source for the operator for the list of additional configuration properties available for Helidon applications.

## Generic Container Components
Coming soon.

## Connections
Within a Verrazzano model, you can define the following connection types:

* REST
* Coherence
* Database
* Ingress

### REST Connections
You can define a REST connection from one component in the model to another component in the same model. When you define a REST connection between components, you can then define variable names that will be provided in the Verrazzano binding. Verrazzano also sets up network policies that enable the components to communicate in the service mesh over TLS.

Settings:

* Target: The name of the target component within the same model
* EnvironmentVariableForHost: The DNS name or IP address of the target component (its Kubernetes service)
* EnvironmentVariableForPort: The port for the target component

### Coherence Connections
You can define a Coherence connection for a component that needs to communicate with a Coherence cluster. The Coherence cluster must also be defined in the same Verrazzano model.

Settings:

* Target: The name of the target Coherence component
* Address: The coherence cluster services address

### Database Connections
In the Verrazzano Model, you can define connections to external databases. These connections then become available to modify in the Verrazzano binding. That is, you can identify a necessary database connection in the model, and then define credentials and the URL for the database in the binding. Verrazzano operators then handle the database connection accordingly.

* Target: name of the database to specify in a Verrazzano binding. That is, in the binding, you will define a database entry that the component will connect to.
* DatasourceName: The name of the data source within the WebLogic configuration that will map to the connected database.

## Related kubectl Commands
TBD
