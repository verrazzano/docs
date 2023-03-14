---
title: "WebLogic domains"
weight: 2
bookHidden: true
---

# WebLogic domains

or components of type "WebLogic domain" - the model/binding is converted into the CR as 
follows: 

```
// pseudocode

if the k8s cluster does not have the micro-operator wls-operator deployed:
    mark this k8s cluster as requiring deployment of wls-operator
    
if the k8s cluster does not have the micro-operator wls-domain deployed:
    mark this k8s cluster a requiring deployment of wls-domain

if there are no other domains in the same k8s cluster (see placement):
    mark this domain as requiring WebLogic operator installation

if there are no other domains in the same namespace (see placement):
    mark this domain as requiring the WebLogic operator targetNamespace list to be updated

if the imagePullSecret was specified:
    mark this domain as requiring a secret to be created

if the target namespace does not exist:
    mark this domain as requiring a namespace to be created

create a domain CR as follows - {{ ... }} indicates where values are substituted in

---
apiVersion: "weblogic.oracle/v4"
kind: Domain
metadata:
  name: {{ component.name  }}
  namespace: {{ component.namespace }}
  labels:
    weblogic.resourceVersion: domain-v2
    weblogic.domainUID: {{ component.name }}
spec:
  domainHome: {{ **NEED** }}
  domainHomeInImage: false
  image: {{ component.image }}
  imagePullPolicy: "IfNotPresent"
  {{ if component.imagePullSecret is specified }}
  imagePullSecrets:
  - name: {{ component.imagePullSecret }}
  {{ end if }}
  webLogicCredentialsSecret: 
    name: {{ component.name }}-domain-credentials
  includeServerOutInPodLog: true
  logHomeEnabled: true
  logHome: {{ **NEED** }}
  serverStartPolicy: "IF_NEEDED"
  serverPod:
    env:
    - name: JAVA_OPTIONS
      value: "-Dweblogic.StdoutDebugEnabled=false"
    - name: USER_MEM_ARGS
      value: "-XX:+UseContainerSupport -Djava.security.egd=file:/dev/./urandom "
    {{ if any env vars are specified - e.g. in a connection of type rest, add them here, one example: }}
    - name: {{ environment_variable_for_host }}
      value: {{ whatever k8s service name "we" (SDO) allocated that component }}
    {{ end if }}
  adminServer:
    serverStartState: "RUNNING"
    {{ if component.adminPort or component.t3port are specified }}
    adminService:
      channels:
       - channelName: default
         nodePort: {{ component.adminPort }}
       - channelName: T3Channel
         nodePort: {{ component.t3port }}
    {{ end if }}
---

NOTE: NodePorts must be unique across the entire k8s cluster

NOTE: Based on conversation with Ryan 6/25, looks like we need to explicitly list all the clusters and provide
`serverStartState` for each one -- so this will mean we need to get that list from the model.... will update
as new information becomes available. 

// defaulted/infered values

the domain will be configured to send logs to this application's verrazzano-provided opensearch
    if component.logging.type is specified:
        if it is exporter:
            udpate the WebLogicLoggingExporter.yaml in `<domain_home>/config` with the right host/port
            it looks like this: 

            publishHost:  {{ the verrazzano opensearch host }}
            publishPort:  {{ the verrazzano opensearch port }}
            domainUID:  {{ component.name }}
            weblogicLoggingExporterEnabled: true
            weblogicLoggingIndexName:  {{  component.logging.index-pattern if specified, else "wls-"component.name }}
            weblogicLoggingExporterSeverity:  Notice
            weblogicLoggingExporterBulkSize: 1
            weblogicLoggingExporterFilters:
            - filterExpression:  'severity > Warning'

        if it is anything else:
            ignore for now

this application's verrazzano-provided prometheus will be configured to scrape metrics from each pod in this domain
    if component.metrics is specified:
        create a ServiceMonitor object (??? check with Sandeep ???) 
        it looks like this: 

        ** NEED SAMPLE **

iterate over connections:
    if connection is of type ingress:
        create an istio virtual service for this domain (see below)
        create an istio gateway for this service (see below)

    if connection is of type rest:
        if target is in a different k8s cluster (see placement):
            create istio service entry for the remote service
            if istio service gateway for the target k8s cluster does not exist:
                create istio service gateway for the target k8s cluster

    if connection is of type database:
        ignore it for now - we are faking it
        // in real life, we would:
        // generate a sit-cfg file to update the named datasource with the 
        // details from the matching database connection 

    if connection is of type atp:
        if the atp instance exists:
            do nothing
        else:
            provision the atp database (see below)
            copy the atp wallet secret to the target namespace/cluster                
        

// check pre-reqs (from above)

if marked for namespace creation:
    create CR to tell k8s-micro-operator to create the namespace and label it for envoy injection

if marked for secret creation: 
    create CR to tell k8s-micro-operator to create the secret

if marked for WebLogic operator installation:
    create CR to tell WKO-micro-operator to install WKO

if marked for WebLogic operator target namespace update:
    create CR to tell WKO-micro-operator to update targetNamespace list

// now create the domain

create the CR to tell domain-micro-operator to create the actual domain CR in the target cluster/namespace


```

####  Virtual Service

The Istio Virtual Service for a domain looks like this: 

```
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: {{ component.name }}-virtualservice
  namespace: {{ component.namespace }}
spec:
  gateways:
  - {{ component.name }}-gateway
  hosts:
  - '{{ component.connection[ingress].dns_name }}'
  http:
  - match:
    - uri:
        prefix: /console
    - port: 7001
    route:
    - destination:
        host: {{ the service name for the admin server }}.{{ component.namespace }}.svc.cluster.local
        port:
          number: 7001
  tcp:
  - match:
    - port: {{ component.connection[ingress].port }}
    route:
    - destination:
        host: {{ the service name for the cluster service }}.{{ component.namespace }}.svc.cluster.local
        port:
          number: {{ component.connection[ingress].port }}
```


#### Gateway

The Istio Gateway looks like this: 

```
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: {{ component.name }}-gateway
  namespace: {{ component.namespace }}
spec:
  selector:
    istio: ingressgateway
  servers:
  - hosts:
    - '*'
    port:
      name: http
      number: 80
      protocol: HTTP
  - hosts:
    - '*'
    port:
      name: tcp
      number: {{ component.connection[ingress].port }}
      protocol: TCP
```

NOTE: this might not be 100% correct ^^^
