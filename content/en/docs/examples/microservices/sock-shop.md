---
title: "Sock Shop"
weight: 4
linkTitle: Sock Shop
description: "Implementations of the Sock Shop Microservices Demo Application"
aliases:
  - /docs/samples/sock-shop
---

## Before you begin

Install Verrazzano by following the [installation]({{< relref "/docs/setup/install/" >}}) instructions.

**NOTE**: The Sock Shop example application deployment files are contained in the Verrazzano project located at
`<VERRAZZANO_HOME>/examples/sockshop`, where `<VERRAZZANO_HOME>` is the root of the Verrazzano project.


## Deploy the application

This example application provides various implementations of the [Sock Shop Microservices Demo Application](https://microservices-demo.github.io/).
It uses OAM resources to define the application deployment:

* [Coherence and Helidon](https://github.com/oracle/coherence-helidon-sockshop-sample) in the `helidon` subdirectory.
* [Coherence and Micronaut](https://github.com/oracle/coherence-micronaut-sockshop-sample) in the `micronaut` subdirectory.
* [Coherence and Spring](https://github.com/oracle/coherence-spring-sockshop-sample) in the `spring` subdirectory.

{{< alert title="NOTE" color="primary" >}}To run this application in the default namespace:
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl label namespace default verrazzano-managed=true
   ```
</div>
{{< /clipboard >}}

   If you chose the default namespace, you can skip Step 1 and ignore the `-n` option in the rest of the commands.
{{< /alert >}}

1. Create a namespace for the Sock Shop application and add a label identifying the namespace as managed by Verrazzano.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl create namespace sockshop
   $ kubectl label namespace sockshop verrazzano-managed=true
   ```
</div>
{{< /clipboard >}}

2. To deploy the application, apply the Sock Shop OAM resources.  Choose to deploy either the `helidon`, `micronaut`, or `spring` variant:

    For **`helidon`**:
<br>
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl apply -f {{< release_source_url raw=true path=examples/sock-shop/helidon/sock-shop-comp.yaml >}} -n sockshop
   $ kubectl apply -f {{< release_source_url raw=true path=examples/sock-shop/helidon/sock-shop-app.yaml >}} -n sockshop
   ```
</div>
{{< /clipboard >}}

    For **`micronaut`**:
<br>
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl apply -f {{< release_source_url raw=true path=examples/sock-shop/micronaut/sock-shop-comp.yaml >}} -n sockshop
   $ kubectl apply -f {{< release_source_url raw=true path=examples/sock-shop/micronaut/sock-shop-app.yaml >}} -n sockshop
   ```
</div>
{{< /clipboard >}}

    For **`spring`**:
<br>
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl apply -f {{< release_source_url raw=true path=examples/sock-shop/spring/sock-shop-comp.yaml >}} -n sockshop
   $ kubectl apply -f {{< release_source_url raw=true path=examples/sock-shop/spring/sock-shop-app.yaml >}} -n sockshop
   ```
</div>
{{< /clipboard >}}


3. Wait for the Sock Shop application to be ready.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl wait \
      --for=condition=Ready pods \
      --all -n sockshop \
      --timeout=300s
   ```
</div>
{{< /clipboard >}}

## Explore the application

The Sock Shop microservices application implements REST API endpoints including:

- `/catalogue` - Returns the Sock Shop catalog.
This endpoint accepts the `GET` HTTP request method.
- `/register` - POST `{
  "username":"xxx",
  "password":"***",
  "email":"foo@example.com",
  "firstName":"foo",
  "lastName":"bar"
}` to create a user. This
endpoint accepts the `POST` HTTP request method.

**NOTE**:  The following instructions assume that you are using a Kubernetes
environment, such as OKE.  Other environments or deployments may require alternative mechanisms for retrieving addresses,
ports, and such.

Follow these steps to test the endpoints.

1. Get the generated host name for the application.
{{< clipboard >}}
<div class="highlight">

   ```
   $ HOST=$(kubectl get gateways.networking.istio.io \
        -n sockshop \
        -o jsonpath='{.items[0].spec.servers[0].hosts[0]}')
   $ echo $HOST

   # Sample output
   sockshop-appconf.sockshop.11.22.33.44.nip.io
   ```
</div>
{{< /clipboard >}}

1. Get the `EXTERNAL_IP` address of the `istio-ingressgateway` service.
{{< clipboard >}}
<div class="highlight">

  ```
 $ ADDRESS=$(kubectl get service \
      -n istio-system istio-ingressgateway \
      -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
 $ echo $ADDRESS

 # Sample output
 11.22.33.44
   ```   
</div>
{{< /clipboard >}}

1. Access the Sock Shop example application.

   * **Using the command line**
   <br>
   <br>
   a. Get catalogue.
   {{< clipboard >}}
   <div class="highlight">

  ```
  $ curl -sk \
      -X GET \
      https://${HOST}/catalogue \
      --resolve ${HOST}:443:${ADDRESS}

  # Sample output
  [{"count":115,"description":"For all those leg lovers out there....", ...}]

  ```

   </div>
   {{< /clipboard >}}
   b. Add a new user (replace values of username and password).
   {{< clipboard >}}
   <div class="highlight">

  ```
  $ curl -i \
      --header "Content-Type: application/json" --request POST \
      --data '{"username":"foo","password":"****","email":"foo@example.com","firstName":"foo","lastName":"foo"}' \
      -k https://${HOST}/register \
      --resolve ${HOST}:443:${ADDRESS}

  ```

   </div>
   {{< /clipboard >}}
   c. Add an item to the user's cart.
     {{< clipboard >}}
   <div class="highlight">

  ```
  $ curl -i \
      --header "Content-Type: application/json" --request POST \
      --data '{"itemId": "a0a4f044-b040-410d-8ead-4de0446aec7e","unitPrice": "7.99"}' \
      -k https://${HOST}/carts/{username}/items \
      --resolve ${HOST}:443:${ADDRESS}

  # Sample output
  {"itemId":"a0a4f044-b040-410d-8ead-4de0446aec7e","quantity":1,"unitPrice":7.99}

  ```

   </div>
   {{< /clipboard >}}
   d. Get cart items.
   {{< clipboard >}}
   <div class="highlight">

  ```   
  $ curl -i \
      -k https://${HOST}/carts/{username}/items \
      --resolve ${HOST}:443:${ADDRESS}

  # Sample output
  [{"itemId":"a0a4f044-b040-410d-8ead-4de0446aec7e","quantity":1,"unitPrice":7.99}]
  ```

   </div>
   {{< /clipboard >}}


     If you are using `nip.io`, then you do not need to include `--resolve`.

   * **Local testing with a browser**

     Temporarily, modify the `/etc/hosts` file (on Mac or Linux)
     or `c:\Windows\System32\Drivers\etc\hosts` file (on Windows 10),
     to add an entry mapping the host name to the ingress gateway's `EXTERNAL-IP` address.
     For example:
     ```
     11.22.33.44 sockshop.example.com
     ```
     Then, you can access the application in a browser at `https://sockshop.example.com/catalogue`.

     - If you are using `nip.io`, then you can access the application in a browser using the `HOST` variable (for example, `https://${HOST}/catalogue`).  
     - If you are going through a proxy, you may need to add `*.nip.io` to the `NO_PROXY` list.

   * **Using your own DNS name**

     Point your own DNS name to the ingress gateway's `EXTERNAL-IP` address.

     * In this case, you would need to edit the `sock-shop-app.yaml` file
       to use the appropriate value under the `hosts` section (such as `yourhost.your.domain`),
       before deploying the Sock Shop application.
     * Then, you can use a browser to access the application at `https://<yourhost.your.domain>/catalogue`.

1. A variety of endpoints associated with the deployed application are available to further explore the logs, metrics, and such.
You can access them according to the directions [here]({{< relref "/docs/setup/access/#get-the-consoles-urls" >}}).

## Verify the deployed application

1. Verify that the application configuration, component, workload, and ingress trait all exist.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl get ApplicationConfiguration -n sockshop
   $ kubectl get Component -n sockshop
   $ kubectl get VerrazzanoCoherenceWorkload -n sockshop
   $ kubectl get IngressTrait -n sockshop
   ```   
</div>
{{< /clipboard >}}

1. Verify that the Sock Shop service pods are successfully created and transition to the `READY` state. Note that this may take a few minutes and that you may see some of the services terminate and restart.
{{< clipboard >}}
<div class="highlight">

  ```
  $ kubectl get pods -n sockshop

  # Sample output
  NAME             READY   STATUS        RESTARTS   AGE
  carts-coh-0      1/1     Running       0          41s
  catalog-coh-0    1/1     Running       0          40s
  orders-coh-0     1/1     Running       0          39s
  payment-coh-0    1/1     Running       0          37s
  shipping-coh-0   1/1     Running       0          36s
  users-coh-0      1/1     Running       0          35s
  ```
</div>
{{< /clipboard >}}

## Undeploy the application

1. To undeploy the application, delete the Sock Shop OAM resources.  Choose to undeploy either the `helidon`, `micronaut`, or `spring` variant.

    For **`helidon`**:
<br>
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl delete -f {{< release_source_url raw=true path=examples/sock-shop/helidon/sock-shop-comp.yaml >}} -n sockshop
   $ kubectl delete -f {{< release_source_url raw=true path=examples/sock-shop/helidon/sock-shop-app.yaml >}} -n sockshop
   ```
</div>
{{< /clipboard >}}

    For **`micronaut`**:
<br>
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl delete -f {{< release_source_url raw=true path=examples/sock-shop/micronaut/sock-shop-comp.yaml >}} -n sockshop
   $ kubectl delete -f {{< release_source_url raw=true path=examples/sock-shop/micronaut/sock-shop-app.yaml >}} -n sockshop
   ```
</div>
{{< /clipboard >}}

   For **`spring`**:
<br>
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl delete -f {{< release_source_url raw=true path=examples/sock-shop/spring/sock-shop-comp.yaml >}} -n sockshop
   $ kubectl delete -f {{< release_source_url raw=true path=examples/sock-shop/spring/sock-shop-app.yaml >}} -n sockshop
   ```
</div>
{{< /clipboard >}}



2. Delete the namespace `sockshop` after the application pods are terminated.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl delete namespace sockshop
   ```
</div>
{{< /clipboard >}}
