---
title: "Verrazzano Application Model"
weight: 1
bookCollapseSection: true
---

# The Verrazzano Application Model



{{< hint danger >}}
** Important ** The details on this page are subject to change.
{{< /hint >}}


The Verrazzano Model (vm kubectl resource) is a Kubernetes Custom Resource Definition that is added to the Verrazzano management cluster. This CRD describes a "Verrazzano Application," which is made up of one or more components.  Components can be WebLogic domains, Coherence clusters, Helidon microservices, or other generic container workloads.  The model also defines connections between components, ingresses to an application, and connections to external services, such as a database or a REST endpoint. Conceptually, the model captures information about the application which does not vary based on where the application is deployed.  A Verrazzano Binding (vb kubectl resource) is then used to map the Verrazzano application defined in the model to the deployment environment. For example, the WebLogic domain X always talks to database Y, no matter how many times this application is deployed. In a particular instance or deployment of the application, e.g. the "test" instance, there may be different credentials and a different URL to access the test version of Y database, but X always talks to Y. The application ***model*** then must define a connection to the database, but the actual credentials and URL used when the application is deployed is defined in the ***binding***. Bindings map the application to the environment.

The combination of a model and and binding produces an instance of an application.
Both the model and binding are meant to be sparse - they contain only the information
that is needed from the user.  Anything that Verrazzano can infer or use a default value can be omitted from these files.

## Structure of the `VerrazzanoApplicationModel`

```
VerrazzanoApplicationModel
    name                                        the name of the model
    description                                 a description of the model
    []weblogicDomains
        -name                                   the name of the component. This is the name used within the application model only.
         adminPort                              external port number for admin console
         t3Port                                 external port number for T3
         domainCRValues                         domain CR values, can provide valid Domain CR values accepted by the WebLogic Kubernetes Operator, with a few exceptions 
            domainUID                           the WebLogic domain name
            domainHome                          path to WebLogic domain home in the image
            image                               the docker image to use for pods in the WebLogic domain
            logHome                             path to log home for the WebLogic domain
            logHomeEnabled                      enables the WebLogic Kubernetes Operator to override the domain log location
            webLogicCredentialsSecret
                name                            the secret containing admin credentials for the WebLogic domain
            imagePullSecrets
                name                            the name of secret for pulling docker images for the WebLogic domain
            clusters                            optional list of clusters for which additional configuration is needed
                clusterName                     the name of the WebLogic cluster
                serverStartState                the desired start state for managed servers in the cluster: ADMIN or RUNNING (default)
                serverPod                       configuration affecting server pods for WebLogic Server instances in the cluster
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
        -connections                            a list of connections for the WebLogic domain
           []-rest                              connections of type REST needed by the WebLogic domain
              target                            the name of the target component
              -environmentVariableForHost       the dns name of the target component (its Kubernetes service)
              -environmentVariableForPort       the port for the target component
            []-ingress
              -name                             the name of the ingress to connect to the domain
            []-database
              target                            the name of the target component (defined in the model)
              datasourceName                    the JDBC data source name within the WebLogic domain configuration for the database
            []-coherence
              target                            the name of the target component (defined in the model)
              address                           the coherence cluster services address
    []-coherenceClusters
        - name                                  the name of component and Coherence cluster
          image
          imagePullSecrets
          cacheConfig
          pofConfig
          []-connections
            []-rest                              connections of type REST needed by the Coherence cluster
               target                            the name of the target component
               -environmentVariableForHost       the dns name of the target component (its Kubernetes service)
               -environmentVariableForPort       the port for the target component
            []-ingress
               -name                             the name of the ingress to connect to the cluster
            []-database
               target                            the name of the target component (defined in the model)
            []-coherence
              target                            the name of the target component (defined in the model)
              address                           the coherence cluster services address
    []-helidonApplications
        name                                    the name of the component
        image                                   the docker image:tag that runs the application
        -imagePullSecret                        name of secret containing credentials for pulling image
        []-connections                          See definition weblogicDomains
           []-rest                              connections of type REST needed by the Helidon application
              target                            the name of the target component
              -environmentVariableForHost       the dns name of the target component (its Kubernetes service)
              -environmentVariableForPort       the port for the target component
           []-ingress
              -name                             the name of the ingress to connect to the application
           []-database
              target                            the name of the target component (defined in the model)
           []-coherence
              target                            the name of the target component (defined in the model)
              address      
        
```

Here is an example `VerrazzanoApplicationModel`:

```yaml
apiVersion: verrazzano.io/v1beta1
kind: VerrazzanoModel
metadata:
  name: bobs-books-model
  namespace: default
spec:
  description: "Bob's Books model"
  weblogicDomains:
    - name: bobbys-front-end
      adminPort: 32701
      t3Port: 32702
      domainCRValues:
        domainUID: bobbys-front-end
        domainHome: /u01/oracle/user_projects/domains/bobbys-front-end
        image: phx.ocir.io/stevengreenberginc/bobbys-front-end:324813
        logHome: /u01/oracle/user_projects/domains/bobbys-front-end/logs
        logHomeEnabled: false
        includeServerOutInPodLog: true
        replicas: 1
        webLogicCredentialsSecret:
          name: bobbys-front-end-weblogic-credentials
        imagePullSecrets:
          - name: ocir
        clusters:
          - clusterName: cluster-1
        serverPod:
          env:
            - name: JAVA_OPTIONS
              value: "-Dweblogic.StdoutDebugEnabled=false"
            - name: USER_MEM_ARGS
              value: "-Djava.security.egd=file:/dev/./urandom -Xms64m -Xmx256m "
            - name: WL_HOME
              value: /u01/oracle/wlserver
            - name: MW_HOME
              value: /u01/oracle
      connections:
        - ingress:
            - name: bobbys-ingress
              match:
                - uri:
                    prefix: "/bobbys-front-end"
        - rest:
            - target: "bobbys-helidon-stock-application"
              environmentVariableForHost: "HELIDON_HOSTNAME"
              environmentVariableForPort: "HELIDON_PORT"
    - name: bobs-bookstore
      adminPort: 32401
      t3Port: 32402
      domainCRValues:
        domainUID: bobs-bookstore
        domainHome: /u01/oracle/user_projects/domains/bobs-bookstore
        image: phx.ocir.io/stevengreenberginc/bobs-bookstore-order-manager:324813
        logHome: /u01/oracle/bobs-bookstore/logs
        logHomeEnabled: false
        includeServerOutInPodLog: true
        replicas: 2
        webLogicCredentialsSecret:
          name: bobs-bookstore-weblogic-credentials
        imagePullSecrets:
          - name: ocir
        clusters:
          - clusterName: cluster-1
        serverPod:
          env:
            - name: JAVA_OPTIONS
              value: "-Dweblogic.StdoutDebugEnabled=false"
            - name: USER_MEM_ARGS
              value: "-Djava.security.egd=file:/dev/./urandom -Xms64m -Xmx256m "
            - name: WL_HOME
              value: /u01/oracle/wlserver
            - name: MW_HOME
              value: /u01/oracle
            - name: DB_ADMIN_USER
              valueFrom:
                secretKeyRef:
                  name: books-wallet
                  key: user_name
            - name: DB_ADMIN_PWD
              valueFrom:
                secretKeyRef:
                  name: books-passphrase
                  key: password
            - name: WALLET_PWD
              valueFrom:
                secretKeyRef:
                  name: books-passphrase
                  key: walletPassword
            - name: TNS_ADMIN
              value: /db/wallet
          volumeMounts:
            - name: creds
              mountPath: /db/wallet      
          initContainers:
          ...

      connections:
        - ingress:
            - name: bobs-ingress
              match:
                - uri:
                    prefix: "/bobs-bookstore-order-manager"
        - atp:
            - target: books  
  helidonApplications:
    - name: "bobbys-helidon-stock-application"
      image: "phx.ocir.io/stevengreenberginc/bobbys-helidon-stock-application:428201"
      imagePullSecrets:
        - name: ocir
      connections:
        - coherence:
            - target: "bobbys-coherence"
              address: "bobbys-coherence-wka"
        - rest:
            - target: "bobs-bookstore"
              environmentVariableForHost: "BACKEND_HOSTNAME"
              environmentVariableForPort: "BACKEND_PORT"
    - name: "roberts-helidon-stock-application"
      image: "phx.ocir.io/stevengreenberginc/roberts-helidon-stock-application:428201"
      imagePullSecrets:
        - name: ocir
      connections:
        - ingress:
            - name: "roberts-ingress"
        - coherence:
            - target: "roberts-coherence"
              address: "roberts-coherence-wka"
  coherenceClusters:
    - name: "bobbys-coherence"
      image: "phx.ocir.io/stevengreenberginc/bobbys-coherence:324813"
      imagePullSecrets:
        - name: ocir # secret to pull bobbys-coherence image from OCIR
        - name: ocr  # secret to pull container-registry.oracle.com/middleware/coherence:12.2.1.4.0
      cacheConfig: "bobbys-cache-config.xml"
      pofConfig: "bobbys-pof-config.xml"
    - name: "roberts-coherence"
      image: "phx.ocir.io/stevengreenberginc/roberts-coherence:324813"
      imagePullSecrets:
        - name: ocir # secret to pull roberts-coherence image from OCIR
        - name: ocr  # secret to pull container-registry.oracle.com/middleware/coherence:12.2.1.4.0
      cacheConfig: "books-cache-config.xml"
      pofConfig: "books-pof-config.xml"
      connections:
        - rest:
            - target: "bobs-bookstore"
              environmentVariableForHost: "BACKEND_HOSTNAME"
              environmentVariableForPort: "BACKEND_PORT"
```

## Deployment Behavior
When a Verrazzzano application is deployed, Verrazzano pushes custom resources to the managed clusters. Within the managed cluster, the component operator interprets the custom resource and deploys the component as defined. For example, if a WebLogic domain is defined in the model, Verrazzano pushes the WebLogic domain custom resource to the appriate managed cluster, and in that cluster, the WebLogic Kubernetes Operator deploys the domain as specified in the model. It is important to understand that the Verrazzano Model can contain custom resource specifications that the component operators (WebLogic, Coherence, and Helidon) can interpret. Much of the necessary component specification is included here, but complete documentation is included in the documentation for the component operator.

See the following additional documentation:

* WebLogic Kubernetes Operator Reference: [https://oracle.github.io/weblogic-kubernetes-operator/userguide/managing-domains/domain-resource/#domain-resource-spec-elements](https://oracle.github.io/weblogic-kubernetes-operator/userguide/managing-domains/domain-resource/#domain-resource-spec-elements)
* Coherence Operator Reference: [https://oracle.github.io/coherence-operator/docs/2.1.0/#/clusters/010_introduction](https://oracle.github.io/coherence-operator/docs/2.1.0/#/clusters/010_introduction)

## WebLogic Domain Components
WebLogic domain components in a Verrazzano model represent the custom resource for the domain that is managed by the WebLogic Kubernetes Operator. Because the operator is what manages the domain, CR options that the model can handle are acceptable as entries in the component within the model file.

{{< hint working >}}
Limitations:

* Verrazzano uses WebLogic Kubernetes Operator version 2.6. Any features or values added in latger versions of the operator are not valid.
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

 For a full list of valid CR values, see the WebLogic Kubernetes Operator repository at [https://github.com/oracle/weblogic-kubernetes-operator/blob/master/docs/domains/Domain.md](https://github.com/oracle/weblogic-kubernetes-operator/blob/master/docs/domains/Domain.md).
 

## Coherence Cluster Components
Note that support for Coherence is an experimental feature in this release of Verrazzano.

Verrazzano relies on version 2.1.1 of the [Coherence Operator](https://github.com/oracle/coherence-operator).  See the documentation at [https://oracle.github.io/coherence-operator/docs/2.1.1/#/clusters/010_introduction](https://oracle.github.io/coherence-operator/docs/2.1.1/#/clusters/010_introduction). For the Coherence Clusters section of the Verrazzano model, valid values are determined by the Coherence operator.

A Coherence cluster component must have the following item:
* name

Coherence cluster components typically have the following items:
* image
* imagePullSecrets
* cacheConfig
* pof
* roles


## Helidon Application Components
Helidon applications must have the following items defined in the model file:
* name
* image
* imagePullSecrets

Helidon applications typically have connections defined as part of the components specification, including REST, database, Coherence, and Ingress connections as described for the previous component types.

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
You can define a REST connection from one component in the model to another component in the same model. When you define a REST connection between components, you can then define variable names that will be provided in the Verrazzano binding. Verrazzano also sets up netowrk policies that enable the components to communicate in the service mesh over TLS.

Settings:

* target: The name of the target component within the same model
* EnvironmentVariableForHost: The dns name or IP Address of the target component (its k8s service)
* EnvironmentVariableForPort: The port for the target component

### Coherence Connections
You can define a Coherence connection for a component that needs to communicate with a Coherence cluster. The Coherence cluster must also be defined in the same Verrazzano model.

Settings:

* Target: The name of the target Coherence component
* Address: The coherence cluster services address

### Database Connections
In the Verrazzano Model, you can define connections to external databases. These connections then become available to modify in the Verrazzano binding. That is, you can identify a necessary database connection in the model, and then define credentials and the URL for the database in the binding. Verrazzano operators then handle the database connection accordingly. 

* Target: name of the database to specify in a Verrazzano binding. That is, in the binding, you will define a database entry that the component will connect to.
* DatasourceName: The name of the datasource within the WebLogic configuration that will map to the connected database.


## Logic

The combination of a model and and binding produces an instance of an application.
Both the model and binding are meant to be sparse - they contain only the information
that is needed from the user.  Anything that Verrazzano can infer or default is omited from
these files.

When a binding CRD is created, Verrazzano proceeds as follows:

```
// pseudocode

// phase 1 - build the "to be" state
build a list "components" from the model, include all details under each component

iterate over the bindings file
for each binding:
    if you can find the matching connection in the "to be" state
        update the connection with the information in the binding
    else
        abort

for each placement:
    if you can find the matching component in the "to be" state
        update the component with its placement information
    else
        abort

// phase 2 - build the "current" state

iterate over the "to be" state
for each component:
    if that component already exists:
        if the config matches the "to be" state
            nothing to do, continue
    else
        mark the component to be created or updated (which is pretty much the same thing)

// phase 3 - initiate updates

iterate over the "to be" state
for each component:
    if the component is marked for create/update
        create the CR that describes this component (* see below *)

```
