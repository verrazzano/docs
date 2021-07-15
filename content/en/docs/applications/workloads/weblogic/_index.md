---
title: "WebLogic and Verrazzano"
description: "Developing WebLogic applications with Verrazzano"
weight: 6
draft: false
---

WebLogic server platform is a widely used enterprise application server for managing JEE based applications and is [certified]
(https://blogs.oracle.com/weblogicserver/weblogic-server-certification-on-kubernetes) to run on Kubernetes using the [WebLogic Kubernetes Operator](https://github.com/oracle/weblogic-kubernetes-operator). Verrazzano installs WebLogic operator as one of its main components and supports deploying WebLogic applications as [VerrazzanoWebLogicWorkload](../../../reference/API/OAM/Workloads#verrazzanoweblogicworkload).

## Deploying WebLogic applications in Verrazzano

1. **Create WebLogic Domain Application image**: To deploy a WebLogic Domain in Kubernetes, we first need to create a Docker Image for the application. For example follow the instructions given in [Example Image with a WLS Domain](https://github.com/oracle/docker-images/tree/main/OracleWebLogic/samples/12213-domain-home-in-image-wdt) to create a WebLogic Domain image using [Oracle WebLogic Deploy Tooling (WDT)](https://github.com/oracle/weblogic-deploy-tooling).
1. **Create VerrazzanoWebLogicWorkload Component**: In order to deploy and run the WebLogic Application image in Verrazzano, create the ***VerrazzanoWebLogicWorkload*** Component that will specify the definition and parameters for the WebLogic Domain contained in the image. See [todo-domain example](../../../reference/API/OAM/Workloads#verrazzanoweblogicworkload) for the example ***VerrazzanoWebLogicWorkload*** Component resource created for a sample domain. For all the option supported by the Domain configuration, see [Domain.md](https://github.com/oracle/weblogic-kubernetes-operator/blob/main/documentation/domains/Domain.md).
1. **Create ApplicationConfiguration for WebLogic application**: Next we need to create an ***ApplicationConfiguration*** that will use the ***VerrazzanoWebLogicWorkload*** Component we created for the Domain. See [todo application](../../../samples/vz-application.yaml) for an example ***ApplicationConfiguration*** using a ***VerrazzanoWebLogicWorkload*** Component.
1. **Verify Domain**: Verrazzano creates the underlying ***Domain*** Kubernetes resource from the ***VerrazzanoWebLogicWorkload*** Component which is further processed by the ***WebLogic Kubernetes Operator*** to create admin/managed server pods and deploy the applications/resources associated with the Domain. Simplest way to verify that the Domain is up and running is to follow the steps mentioned in [verify-the-domain](https://oracle.github.io/weblogic-kubernetes-operator/samples/simple/domains/domain-home-in-image/#verify-the-domain) section.

## Lift and Shift WebLogic applications

Verrazzano makes it easy for WebLogic application to migrate from on-premises installations to the cloud. See the [lift-and-shift](../../../samples/lift-and-shift.md) guide for detailed instructions.


## Database Connection

WebLogic applications typically make database connections using the connection information present in the ***JDBCSystemResources*** created in WebLogic domain. In order to implement this in Verrazzano, databases will deployed as separate components and the connection information made available to the Domain using the WDT Model.

1. **Deploy the Database in Verrazzano**: To deploy a database, we need to create the corresponding ***Component*** and ***ApplicationConfiguration*** that will run the database in a pod and expose its connection information as a ***Service***. For example, look at [tododomain-mysql](../../../samples/mysql-oam.yaml) descriptor.
1. **Create WebLogic resource ConfigMap**: Next we create a ***ConfigMap*** that will contain the definition of ***JDBCSystemResource*** with connection information for the database.. For example, see the definition of ***tododomain-configmap*** in [sample application configguration](../../../samples/vz-application.yaml).
1. **Configure Domain to use the WebLogic resource ConfigMap**: The ***ConfigMap*** containing resource information for ***JDBCSystemResource*** can be configured in the ***configuration*** section of the ***VerrazzanoWebLogicWorkload*** Component of teh Domain.
   
```yaml
...
    configuration:
        introspectorJobActiveDeadlineSeconds: 900
        model:
            configMap: tododomain-configmap
            domainType: WLS
...
```

See [sample application configguration](../../../samples/vz-application.yaml) for more details.

## Ingresses

To access the endpoints for a JEE application deployed as part of a ***VerrazzanoWebLogicWorkload*** Component, Verrazzano provides a feature to specify an ***IngressTrait*** for the Component which is then translated to an [Istio Ingress Gateway](https://istio.io/latest/docs/reference/config/networking/gateway/) and [VirtualService](https://istio.io/latest/docs/reference/config/networking/virtual-service/) by Verrazzano. For example, look at [sample application](../../../samples/vz-application.yaml) where the ***IngressTrait*** is configured for the application endpoint.

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

The endpoint can then be accessed using the Istio Gateway created by Verrazzano, as described in [Access the ToDo List application](../../../samples/todo-list.md) section.

```
$ HOST=$(kubectl get gateway -n todo-list -o jsonpath={.items[0].spec.servers[0].hosts[0]})
$ ADDRESS=$(kubectl get service -n istio-system istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
$ curl -sk https://${HOST}/todo/ --resolve ${HOST}:443:${ADDRESS}
```

## Limitations with Containerized WebLogic applications

1. **Connectivity and Storage for Databases**: Typically enterprise WebLogic applications communicate with externally hosted databases and when these applications are migrated to Verrazzano, we need to make sure that either these databases are migrated to the Verrazzano or we need to make sure that the WebLogic Domains are correctly configured to connect to external databases and the connectivity exists between the Kubernetes cluster and the database. Also when new database deployments are setup in Verrazzano or existing ones are migrated, it will be required to configure external storage for the data using ***PersistentVolume**. For example, look at the [instructions](https://github.com/oracle/docker-images/blob/main/OracleDatabase/SingleInstance/helm-charts/oracle-db/README.md) for deploying a Single Instance Oracle Database in Kubernetes using PV.
1. **Deploying JEE Applications in Domain**: When a external JEE application archive is deployed to an existing Domain deployed in Kubernetes, the configuration of deployed Domain can become out of sync with the Domain model in image. To avoid suh issues, it is a best practice to include all the applications to be deployed in a Domain within the Domain image itself. For this and other such best practices for deploying WebLogic applications in Kubernetes, see the following [link](https://blogs.oracle.com/weblogicserver/best-practices-for-application-deployment-on-weblogic-server-running-on-kubernetes-v2).





