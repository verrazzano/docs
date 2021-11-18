---
title: "Bob's Books"
weight: 7
description: "An example application based on WebLogic, Helidon, and Coherence"
---

## Before you begin

* Install Verrazzano by following the [installation]({{< relref "/docs/setup/install/installation.md" >}}) instructions.
* To download the example image, you must first accept the license agreement.
  * In a browser, navigate to https://container-registry.oracle.com/ and sign in.
  * Search for `example-bobbys-coherence`, `example-bobbys-front-end`, `example-bobs-books-order-manager`, and `example-roberts-coherence`.
  * For each, select the image name in the results, click Continue, then read and accept the license agreement.

   **NOTE:** The Bob's Books example application deployment files are contained in the Verrazzano project located at
   `<VERRAZZANO_HOME>/examples/bobs-books`, where `<VERRAZZANO_HOME>` is the root of the Verrazzano project.

## Overview

Bob's Books consists of three main parts:

* A back-end "order processing" application, which is a Java EE
  application with REST services and a very simple JSP UI, which
  stores data in a MySQL database.  This application runs on WebLogic
  Server.
* A front-end web store "Robert's Books", which is a general book
  seller.  This is implemented as a Helidon microservice, which
  gets book data from Coherence, uses a Coherence cache store to persist
  data for the order manager, and has a React web UI.
* A front-end web store "Bobby's Books", which is a specialty
  children's book store.  This is implemented as a Helidon
  microservice, which gets book data from a (different) Coherence cache store,
  interfaces directly with the order manager,
  and has a JSF web UI running on WebLogic Server.

For more information and the source code of this application, see the [Verrazzano Examples](https://github.com/verrazzano/examples).

## Deploy the example application

1. Create a namespace for the example and add a label identifying the namespace as managed by Verrazzano.

    ```
    $ kubectl create namespace bobs-books
    $ kubectl label namespace bobs-books verrazzano-managed=true istio-injection=enabled
    ```

1. Create a `docker-registry` secret to enable pulling the example image from the registry.
   ```
   $ kubectl create secret docker-registry bobs-books-repo-credentials \
           --docker-server=container-registry.oracle.com \
           --docker-username=YOUR_REGISTRY_USERNAME \
           --docker-password=YOUR_REGISTRY_PASSWORD \
           --docker-email=YOUR_REGISTRY_EMAIL \
           -n bobs-books
   ```

   Replace `YOUR_REGISTRY_USERNAME`, `YOUR_REGISTRY_PASSWORD`, and `YOUR_REGISTRY_EMAIL`
   with the values you use to access the registry.  

1. Create secrets for the WebLogic domains:
    ```
    # Replace the values of the WLS_USERNAME and WLS_PASSWORD environment variables as appropriate.
    $ export WLS_USERNAME=<username>
    $ export WLS_PASSWORD=<password>
    $ kubectl create secret generic bobbys-front-end-weblogic-credentials \
        --from-literal=password=$WLS_PASSWORD \
        --from-literal=username=$WLS_USERNAME \
        -n bobs-books

    $ kubectl create secret generic bobs-bookstore-weblogic-credentials \
        --from-literal=password=$WLS_PASSWORD \
        --from-literal=username=$WLS_USERNAME \
        -n bobs-books

    $ kubectl create secret generic mysql-credentials \
        --from-literal=username=$WLS_USERNAME \
        --from-literal=password=$WLS_PASSWORD \
        --from-literal=url=jdbc:mysql://mysql.bobs-books.svc.cluster.local:3306/books \
        -n bobs-books
    ```
   Note that the example application is preconfigured to use specific secret names.
   For the source code of this application, see the [Verrazzano Examples](https://github.com/verrazzano/examples).
   If you want to use secret names that are different from what is specified in the source code, you will need to update the corresponding YAML file and rebuild the Docker images for the example application.

1. To deploy the application, apply the example resources.
   ```
   $ kubectl apply -f {{< release_source_url raw=true path=examples/bobs-books/bobs-books-comp.yaml >}}
   $ kubectl apply -f {{< release_source_url raw=true path=examples/bobs-books/bobs-books-app.yaml >}}
   ```

1. Wait for all of the pods in the Bob's Books example application to be ready.
   You can monitor their progress by listing the pods and inspecting the output, or you can use the `kubectl wait` command.  

   You may need to repeat the `kubectl wait` command several times before it is successful.
   The WebLogic Server and Coherence pods may take a while to be created and `Ready`.
   ```
   $ kubectl get pods -n bobs-books

   # -or- #

   $ kubectl wait \
       --for=condition=Ready pods \
       --all -n bobs-books \
       --timeout=600s
   ```

1. Get the `EXTERNAL_IP` address of the `istio-ingressgateway` service.
    ```
    $ ADDRESS=$(kubectl get service \
        -n istio-system istio-ingressgateway \
        -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    $ echo $ADDRESS
   
    # Sample output
    11.22.33.44
    ```

1. Get the generated host name for the application.
   ```
   $ HOST=$(kubectl get gateway bobs-books-bobs-books-gw \
       -n bobs-books \
       -o jsonpath='{.spec.servers[0].hosts[0]}')
   $ echo $HOST
   
   # Sample output
   bobs-books.bobs-books.11.22.33.44.nip.io
   ```

1. Access the application. To access the application in a browser, you will need to do one of the following:
    * **Option 1:** If you are using `nip.io`, then you can access the application using the generated host name. For example:

      * Robert's Books UI at `https://bobs-books.bobs-books.11.22.33.44.nip.io/`.

      * Bobby's Books UI at `https://bobs-books.bobs-books.11.22.33.44.nip.io/bobbys-front-end/`.

      * Bob's order manager  UI at `https://bobs-books.bobs-books.11.22.33.44.nip.io/bobs-bookstore-order-manager/orders`.

    * **Option 2:** Temporarily, modify the `/etc/hosts` file (on Mac or Linux) or `c:\Windows\System32\Drivers\etc\hosts` file (on Windows 10), to add an entry mapping the host used by the application to the external IP address assigned to your gateway. For example:
      ```
      11.22.33.44 bobs-books.example.com
      ```
      Then, you can use a browser to access the application, as shown:

      * Robert's Books UI at `https://bobs-books.example.com/`.

      * Bobby's Books UI at `https://bobs-books.example.com/bobbys-front-end/`.

      * Bob's order manager  UI at `https://bobs-books.example.com/bobs-bookstore-order-manager/orders`.

    * **Option 3:** Alternatively, point your own DNS name to the load balancer's external IP address. In this case, you would need to have edited the `bobs-books-app.yaml` file to use the appropriate values under the `hosts` section for the application (such as `your-roberts-books-host.your.domain`), before deploying the application.
      Then, you can use a browser to access the application, as shown:

      * Robert's Books UI at `https://<your-roberts-books-host.your.domain>/`.

      * Bobby's Books UI at `https://<your-bobbys-books-host.your.domain>/bobbys-front-end/`.

      * Bob's order manager UI at `https://<your-bobs-orders-host.your.domain>/`.

## Access the applications using the WLS Administration Console

Use the WebLogic Server Administration Console to access the applications as follows.

{{< alert title="NOTE" color="warning" >}}
It is recommended that the WebLogic Server Administration Console _not_ be exposed publicly.
{{< /alert >}}

### Access bobs-bookstore

1. Set up port forwarding.
   ```
   $ kubectl port-forward pods/bobs-bookstore-adminserver 7001:7001 -n bobs-books
   ```
   **NOTE**: If you are using the OCI Cloud Shell to run `kubectl`, in order to access the WebLogic Server Administration Console using port forwarding, you will need to run `kubectl` on another machine.

1. Access the WebLogic Server Administration Console from your browser.
   ```
   http://localhost:7001/console
   ```

### Access bobbys-front-end

1. Set up port forwarding.
   ```
   $ kubectl port-forward pods/bobbys-front-end-adminserver 7001:7001 -n bobs-books
   ```
   **NOTE**: If you are using the OCI Cloud Shell to run `kubectl`, in order to access the WebLogic Server Administration Console using port forwarding, you will need to run `kubectl` on another machine.

1. Access the WebLogic Server Administration Console from your browser.
   ```
   http://localhost:7001/console
   ```


## Troubleshooting

1. Verify that the application configuration, domains, Coherence resources, and ingress trait all exist.
   ```
   $ kubectl get ApplicationConfiguration -n bobs-books
   $ kubectl get Domain -n bobs-books
   $ kubectl get Coherence -n bobs-books
   $ kubectl get IngressTrait -n bobs-books
   ```   

1. Verify that the service pods are successfully created and transition to the `READY` state.
   Note that this may take a few minutes and that you may see some of the services terminate and restart.
   ```
   $ kubectl get pods -n bobs-books

   NAME                                                READY   STATUS    RESTARTS   AGE
   bobbys-helidon-stock-application-868b5965c8-dk2xb   3/3     Running   0          19h
   bobbys-coherence-0                                  2/2     Running   0          19h
   bobbys-front-end-adminserver                        3/3     Running   0          19h
   bobbys-front-end-managed-server1                    3/3     Running   0          19h
   bobs-bookstore-adminserver                          3/3     Running   0          19h
   bobs-bookstore-managed-server1                      3/3     Running   0          19h
   mysql-669665fb54-9m8wq                              2/2     Running   0          19h
   robert-helidon-96997fcd5-kzjkf                      3/3     Running   0          19h
   robert-helidon-96997fcd5-nlswm                      3/3     Running   0          19h
   roberts-coherence-0                                 2/2     Running   0          17h
   roberts-coherence-1                                 2/2     Running   0          17h
   ```
## Undeploy the application

1. To undeploy the application, delete the Bob's Books OAM resources.
   ```
   $ kubectl delete -f {{< release_source_url raw=true path=examples/bobs-books/bobs-books-app.yaml >}}
   $ kubectl delete -f {{< release_source_url raw=true path=examples/bobs-books/bobs-books-comp.yaml >}}
   ```

1. Delete the namespace `bobs-books` after the application pods are terminated. The secrets created for the WebLogic domain will also be deleted.
   ```
   $ kubectl delete namespace bobs-books
   ```
