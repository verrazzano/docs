---
title: "Bob's Books"
weight: 4
---

# Bob's Books Demo Application

The `Bob's Books` demo application is located in the repository `https://github.com/verrazzano/examples`.

Bob's Books consists of three main parts:

* A backend "order processing" application which is a Java EE
  application with REST services and a very simple JSP UI which
  stores data in a MySQL database.  This application runs on WebLogic
  Server.
* A front end web store "Robert's Books" which is a general book
  seller.  This is implemented as a Helidon microservice which
  gets book data from Coherence, uses a Coherence cache store to persist
  data for the order manager, and has a React web UI.
* A front end web store "Bobby's Books" which is a specialist
  children's book store.  This is implemented as a Helidon
  microservice which gets book data from a (different) Coherence,
  interfaces directly with the order manager,
  and has a JSF Faces web UI running on WebLogic Server.

**TBD - DO WE WANT TO KEEP THIS SECTION, IF SO WE NEED TO CLEAN THIS UP?** When fully deployed, the environment will look like this:

| "onprem" cluster | "cloud" cluster |
| --- | --- |
| **WebLogic 12.2.1.3 components** | **Sauron components** |
| *(ns weblogicx-system)*  istio enabled| *(ns sauron0)* istio disabled |
| weblogicx-service (svc) -> web (port 30000), apiserver (port 31456) | operator |
| fakeworkflow (port 8080) | elasticsearch |
| operatorsvc (port 8080) | kibana |
| domainsvc (port 8080) | prometheus |
| imagebldsvc (port 8080) | grafana |
| k8ssvc (port 8080) | api |
| cohclustersvc (port 8080) | auth |
| mysql-service -> mysql-xxx (port 3306) istio disabled | console |  
| | help |
| | alertmanager |
| **Demo App components** | **Demo App components** |
| *(ns bob)* istio enabled | *(ns bobby)* istio enabled |
| bobs-bookstore-order-manager-cluster-1 (svc) -> bobs-bookstore-managed-server[1..n] | bobbys-front-end (svc) -> bobbys-front-end-managed-server[1..n] |
| bobs-bookstore-admin-server (+ svcs) (port 32402, 32403, 31111) | bobbys-front-end-admin-server (+ svcs) (port 32702, 32703, 31111) |
| bobs-bookstore-weblogic-credentials (sec) | bobbys-front-end-weblogic-credentials (sec) |
| mysql-server (svc) -> mysql-xxx (istio disabled) (port 3306) | bobbys-helidon-stock-application (svc) -> bobbys-helidon-stock-application-xxx |
| | bobbys-coherence (svc) -> bobbys-coherence-[0..n] (istio disabled) |
| | *(ns robert)* istio enabled |
| | roberts-helidon-stock-application (svc) -> roberts-helidon-stock-application-xxx |
| | roberts-coherence (svc) -> roberts-coherence-[0..n] (istio disabled) |
| **Istio** | **Istio** |
| bobs-bookstore (virtual service) | bobs-bookstore (istio service entry) |
| | bobbys-front-end (istio virtual service) |
| | roberts-helidon-stock-application (istio virtual service) |

## How to Deploy the Demo
The files `superdomain/demo-model.yaml` and `superdomain/demo-binding.yaml` define the demo environment.  They assume a verrazzano installation was completed that created a single management cluster and two managed clusters.  The management cluster contains the verrazzano infrastructure components, the managed clusters will be used to run the demo app (e.g. run weblogic domains, coherence and helidon applications).

### Licenses Required
Need to accept license for Coherence and WebLogic Operators

* Login into https://container-registry.oracle.com
* Search for `coherence` and accept the license
* Search for `weblogic` and accept the license


### Create Secrets
The following secrets are required before applying the demo model and binding files.

The secret `ocir` contains the credentials required for pulling the demo docker images.
```text
kubectl create secret docker-registry ocir \
    --docker-server=<DOCKER-SERVER> \
    --docker-username='<DOCKER-USERNAME>' \
    --docker-password='<DOCKER-PASSWORD>' \
    --docker-email=''
```

The secret `ocr` contains the credentials required for pulling the `coherence` docker images.
```text
kubectl create secret docker-registry ocr \
    --docker-server=container-registry.oracle.com \
    --docker-username='<USERNAME>' \
    --docker-password='<PASSWORD>' \
    --docker-email=''
```

The secret `ocicredentials` contains the OCI credentials required to create an Autonomous Database (ATP).
```text
kubectl create secret generic ocicredentials \
    --from-literal=tenancy=<TENANCY-OCID> \
    --from-literal=user=<USER-OCID> \
    --from-literal=fingerprint=<FINGERPRINT> \
    --from-literal=region=<REGION> \
    --from-file=privatekey=<PATH-TO-PRIVATE-KEY> \
    --from-literal=passphrase=“”
```

The secret `atpsecret` contains the credentials to use when creating an ATP instance.
```text
kubectl create secret generic atpsecret \
  --from-literal=password=<ADMIN-PASSWORD> \
  --from-literal=walletPassword=<WALLET-PASSWORD>
```

The secret `bobbys-front-end-weblogic-credentials` contains the credentials required for the WebLogic domain that will be created in the namespace `bobby`.
```text
kubectl create secret generic bobbys-front-end-weblogic-credentials \
  --from-literal=username=<WEBLOGIC-USERNAME> \
  --from-literal=password=<WEBLOGIC-PASSWORD>
```

The secret `bobs-bookstore-weblogic-credentials` contains the credentials required for the WebLogic domain that will be created in the nameapce `bob`.
```text
kubectl create secret generic bobs-bookstore-weblogic-credentials \
  --from-literal=username=<WEBLOGIC-USERNAME> \
  --from-literal=password=WEBLOGIC-PASSWORD>
```

### Customize Demo Model & Binding Files
The binding file for the demo need to be customized as follows for your environment.

For this example assume the following:

- The name of the environment created with the installer was `demo`.  Therefore:
    - The name of managed cluster 1 is `demo-managed-1`
    - The name of managed cluster 2 is `demo-managed-2`

Edit the binding file as indicated here:

* superdmain/demo-binding.yaml
    - Rename `<MANAGED_CLUSTER_1>` to be `demo-managed-1`
    - Rename `<MANAGED_CLUSTER_2>` to be `demo-managed-2`

**Note** - The ATP database name must be unique for each model/binding pair being applied.  If the demo is being deployed more than once, the following edits also need to be performed.  Assume the name of ATP database for the second deployment is `mybooks`

Edit the model and binding files as indicated here:

* superdomain/demo-model.yaml
    - Rename all instances of `books-wallet` to be `mybooks-wallet`
    - Rename all instances of `books-passphrase` to be `mybooks-passphrase`
    - Rename all instances of `books_high` to be `mybooks_high`
* superdmain/demo-binding.yaml
    - Rename ATP binding name to be "mybooks" instead of "books"


### Apply the Demo Model & Binding Files
The model and binding files need to be applied to the management cluster.  The `verrazzano-operator` will detect the model/binding pairing and deploy the demo to the managed clusters.

```text
kubectl apply -f superdomain/demo-model.yaml
kubectl apply -f superdomain/demo-binding.yaml
```

### Verrazzano Endpoints
Example endpoints for an install with the following settings:

* Environment Name: `demo`
* DNS Zone: `verrazzano.demo.com`

| Description| End Point | Credentials |
| --- | --- | --- |
| Rancher Server | https://rancher.demo.verrazzano.demo.com | admin/admin |
| Keycloak | https://keycloak.demo.verrazzano.demo.com | verrazzano/verrazzan0 |
| Verrazzano API | https://api.demo.verrazzano.demo.com | |

### Model/Binding Endpoints
Example endpoints after a model/binding is applies.  Assume the following settings:

* Environment Name: `demo`
* DNS Zone: `verrazzano.demo.com`
* Binding Name: `bobs-books-binding1`
* External IP of istio-gateway on Managed Cluster 1: `100.20.30.40`
    - `kubectl get service istio-ingressgateway -n istio-system`
* External IP of istio-gateway on Managed Cluster 2: `200.20.30.40`

| Description| End Point | Credentials |
| --- | --- | --- |
| Bobby's Books | http://100.20.30.40/bobbys-front-end | |
| Bobby's Books WebLogic Console | http://100.20.30.40/console | weblogic/welcome1 |
| Robert's Books | http://200.20.30.40 | |
| Kibana | https://kibana.vmi.bobs-books-binding1.demo.verrazzano.demo.com | verrazzano/changeme |
| Grafana | https://grafana.vmi.bobs-books-binding1.demo.verrazzano.demo.com | verrazzano/changeme |
| Prometheus | https://prometheus.vmi.bobs-books-binding1.demo.verrazzano.demo.com | verrazzano/changeme |
