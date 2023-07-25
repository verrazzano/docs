---
title: "Multicluster Helidon Sock Shop"
linktitle: "Helidon Sock Shop"
weight: 2
aliases:
  - /docs/samples/multicluster/sock-shop
---

This example application provides a [Helidon](https://helidon.io) implementation of the [Sock Shop Microservices Demo Application](https://microservices-demo.github.io/).
It uses OAM resources to define the application deployment in a multicluster environment.

## Before you begin

* Set up a multicluster Verrazzano environment following the [installation instructions]({{< relref "/docs/setup/mc-install/multicluster.md" >}}).
* The example assumes that there is a managed cluster named `managed1` associated with the multicluster environment.
If your environment does not have a cluster of that name, then you should edit the deployment files and change the cluster name
listed in the `placement` section.

Set up the following environment variables to point to the kubeconfig file for the admin and managed clusters.
{{< clipboard >}}
<div class="highlight">

```
$ export KUBECONFIG_ADMIN=/path/to/your/adminclusterkubeconfig
$ export KUBECONFIG_MANAGED1=/path/to/your/managedclusterkubeconfig
```

</div>
{{< /clipboard >}}

**NOTE**: The Sock Shop application deployment files are contained in the Verrazzano project located at
`<VERRAZZANO_HOME>/examples/multicluster/sockshop`, where `<VERRAZZANO_HOME>` is the root of the Verrazzano project.


## Deploy the application

1. Create a namespace for the Sock Shop application by deploying the Verrazzano project.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN apply \
       -f {{< release_source_url raw=true path=examples/multicluster/sock-shop/verrazzano-project.yaml >}}
   ```

</div>
{{< /clipboard >}}

1. Apply the Sock Shop OAM resources to deploy the application.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN apply \
       -f {{< release_source_url raw=true path=examples/multicluster/sock-shop/sock-shop-comp.yaml >}}
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN apply \
       -f {{< release_source_url raw=true path=examples/multicluster/sock-shop/sock-shop-app.yaml >}}
   ```

</div>
{{< /clipboard >}}

1. Wait for the Sock Shop application to be ready.  It may take a few minutes for the pod resources to start appearing on the managed cluster.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 wait \
       --for=condition=Ready pods \
       --all -n mc-sockshop \
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
  "lastName":"coo"
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
   $ HOST=$(kubectl --kubeconfig $KUBECONFIG_MANAGED1 get gateway \
         -n mc-sockshop \
         -o jsonpath={.items[0].spec.servers[0].hosts[0]})
   $ echo $HOST

   # Sample output
   sockshop-appconf.mc-sockshop.11.22.33.44.nip.io
   ```

</div>
{{< /clipboard >}}

1. Get the `EXTERNAL_IP` address of the `istio-ingressgateway` service.
{{< clipboard >}}
<div class="highlight">

   ```
   $ ADDRESS=$(kubectl --kubeconfig $KUBECONFIG_MANAGED1 get service \
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

## Verify the deployed application

1. Verify that the application configuration, components, workloads, and ingress trait all exist.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get ApplicationConfiguration -n mc-sockshop
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get Component -n mc-sockshop
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get VerrazzanoCoherenceWorkload -n mc-sockshop
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get Coherence -n mc-sockshop
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get IngressTrait -n mc-sockshop
   ```   

</div>
{{< /clipboard >}}

1. Verify that the Sock Shop service pods are successfully created and transition to the `READY` state. Note that this may take a few minutes and that you may see some of the services terminate and restart.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get pods -n mc-sockshop

   # Sample output
   NAME             READY   STATUS    RESTARTS   AGE
   carts-coh-0      2/2     Running   0          38m
   catalog-coh-0    2/2     Running   0          38m
   orders-coh-0     2/2     Running   0          38m
   payment-coh-0    2/2     Running   0          38m
   shipping-coh-0   2/2     Running   0          38m
   users-coh-0      2/2     Running   0          38m
   ```

</div>
{{< /clipboard >}}

1. A variety of endpoints are available to further explore the logs, metrics, and such, associated with
the deployed Sock Shop application.  You can access them according to the directions [here]({{< relref "/docs/setup/access/#get-the-consoles-urls" >}}).

## Undeploy the application

Regardless of its location, to undeploy the application,
delete the application resources and the project from the admin cluster.
Undeploy affects all clusters in which the application is located.

1. To undeploy the application, delete the Sock Shop OAM resources:
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete \
     -f {{< release_source_url raw=true path=examples/multicluster/sock-shop/sock-shop-app.yaml >}}
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete \
     -f {{< release_source_url raw=true path=examples/multicluster/sock-shop/sock-shop-comp.yaml >}}
   ```

</div>
{{< /clipboard >}}

1. Delete the project.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete \
    -f {{< release_source_url raw=true path=examples/multicluster/sock-shop/verrazzano-project.yaml >}}
   ```

</div>
{{< /clipboard >}}

1. Delete the namespace `mc-sockshop` after the application pods are terminated.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete namespace mc-sockshop
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 delete namespace mc-sockshop
   ```

</div>
{{< /clipboard >}}
