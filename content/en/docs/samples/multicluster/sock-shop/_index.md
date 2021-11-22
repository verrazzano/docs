# Multicluster Helidon Sock Shop

This example application provides a [Helidon](https://helidon.io) implementation of the [Sock Shop Microservices Demo Application](https://microservices-demo.github.io/).
It uses OAM resources to define the application deployment in a multicluster environment.

## Before you begin

* Set up a multicluster Verrazzano environment following the [installation instructions]({{< relref "/docs/setup/install/multicluster/_index.md" >}}).
* The example assumes that there is a managed cluster named `managed1` associated with the multicluster environment.
If your environment does not have a cluster of that name, then you should edit the deployment files and change the cluster name
listed in the `placement` section.

Set up the following environment variables to point to the `kubeconfig` for the admin and managed clusters.

```
$ export KUBECONFIG_ADMIN=/path/to/your/adminclusterkubeconfig
$ export KUBECONFIG_MANAGED1=/path/to/your/managedclusterkubeconfig
```

**NOTE:** The Sock Shop application deployment files are contained in the Verrazzano project located at
`<VERRAZZANO_HOME>/examples/multicluster/sockshop`, where `<VERRAZZANO_HOME>` is the root of the Verrazzano project.


## Deploy the Sock Shop application

1. Create a namespace for the Sock Shop application by deploying the Verrazzano project.
   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN apply \
       -f {{< release_source_url raw=true path=examples/multicluster/sock-shop/verrazzano-project.yaml >}}
   ```

1. Apply the Sock Shop OAM resources to deploy the application.
   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN apply \
       -f {{< release_source_url raw=true path=examples/multicluster/sock-shop/sock-shop-comp.yaml >}}
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN apply \
       -f {{< release_source_url raw=true path=examples/multicluster/sock-shop/sock-shop-app.yaml >}}
   ```

1. Wait for the Sock Shop application to be ready.  It may take a few minutes for the pod resources to start appearing on the managed cluster.
   ```
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 wait \
       --for=condition=Ready pods \
       --all -n mc-sockshop \
       --timeout=300s
   ```

## Explore the Sock Shop application

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

Follow these steps to test the endpoints:

1. Get the generated host name for the application.
   ```
   $ HOST=$(kubectl --kubeconfig $KUBECONFIG_MANAGED1 get gateway \
         -n mc-sockshop \
         -o jsonpath={.items[0].spec.servers[0].hosts[0]})
   $ echo $HOST

   # Sample output
   sockshop-appconf.mc-sockshop.11.22.33.44.nip.io
   ```

1. Get the `EXTERNAL_IP` address of the `istio-ingressgateway` service.
   ```
   $ ADDRESS=$(kubectl --kubeconfig $KUBECONFIG_MANAGED1 get service \
       -n istio-system istio-ingressgateway \
       -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
   $ echo $ADDRESS

   # Sample output
   11.22.33.44
   ```   

1. Access the Sock Shop example application:

   * **Using the command line**

     ```
     # Get catalogue
     $ curl -sk \
         -X GET \
         https://${HOST}/catalogue \
         --resolve ${HOST}:443:${ADDRESS}

     # Sample output
     [{"count":115,"description":"For all those leg lovers out there....", ...}]

     # Add a new user (replace values of username and password)
     $ curl -i \
         --header "Content-Type: application/json" --request POST \
         --data '{"username":"foo","password":"****","email":"foo@example.com","firstName":"foo","lastName":"foo"}' \
         -k https://${HOST}/register \
         --resolve ${HOST}:443:${ADDRESS}

     # Add an item to the user's cart
     $ curl -i \
         --header "Content-Type: application/json" --request POST \
         --data '{"itemId": "a0a4f044-b040-410d-8ead-4de0446aec7e","unitPrice": "7.99"}' \
         -k https://${HOST}/carts/{username}/items \
         --resolve ${HOST}:443:${ADDRESS}

     # Sample output
     {"itemId":"a0a4f044-b040-410d-8ead-4de0446aec7e","quantity":1,"unitPrice":7.99}

     # Get cart items
     $ curl -i \
         -k https://${HOST}/carts/{username}/items \
         --resolve ${HOST}:443:${ADDRESS}

     # Sample output
     [{"itemId":"a0a4f044-b040-410d-8ead-4de0446aec7e","quantity":1,"unitPrice":7.99}]
     ```
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

     If you are using `nip.io`, then you can access the application in a browser using the `HOST` variable (for example, `https://${HOST}/catalogue`).  If you are going through a proxy, you may need to add `*.nip.io` to the `NO_PROXY` list.

   * **Using your own DNS name**

     * Point your own DNS name to the ingress gateway's `EXTERNAL-IP` address.
     * In this case, you would need to edit the `sock-shop-app.yaml` file
       to use the appropriate value under the `hosts` section (such as `yourhost.your.domain`),
       before deploying the Sock Shop application.
     * Then, you can use a browser to access the application at `https://<yourhost.your.domain>/catalogue`.

## Troubleshooting

1. Verify that the application configuration, components, workloads, and ingress trait all exist.
   ```
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get ApplicationConfiguration -n mc-sockshop
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get Component -n mc-sockshop
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get VerrazzanoCoherenceWorkload -n mc-sockshop
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get Coherence -n mc-sockshop
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get IngressTrait -n mc-sockshop
   ```   

1. Verify that the Sock Shop service pods are successfully created and transition to the `READY` state. Note that this may take a few minutes and that you may see some of the services terminate and restart.
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
1. A variety of endpoints are available to further explore the logs, metrics, and such, associated with
the deployed Sock Shop application.  Accessing them may require the following:

    - Run this command to get the password that was generated for the telemetry components:
        ```
        $ kubectl --kubeconfig $KUBECONFIG_ADMIN get secret \
            --namespace verrazzano-system verrazzano \
            -o jsonpath={.data.password} | base64 \
            --decode; echo
        ```
        The associated user name is `verrazzano`.

    - You will have to accept the certificates associated with the endpoints.

    You can retrieve the list of available ingresses with following command:

    ```
    $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get ingress -n verrazzano-system
    NAME                    CLASS    HOSTS                                              ADDRESS       PORTS     AGE
    verrazzano-ingress      <none>   verrazzano.default.10.11.12.13.nip.io              10.11.12.13   80, 443   32m
    vmi-system-prometheus   <none>   prometheus.vmi.system.default.10.11.12.13.nip.io   10.11.12.13   80, 443   32m
     ```  

    Using the ingress host information, some of the endpoints available are:

    | Description| Address | Credentials |
    | --- | --- | --- |
    | Prometheus | `https://[vmi-system-prometheus ingress host]` | `verrazzano`/`telemetry-password` |    

## Undeploy the Sock Shop application

Regardless of its location, to undeploy the application,
delete the application resources and the project from the admin cluster.
Undeploy affects all clusters in which the application is located.

1. To undeploy the application, delete the Sock Shop OAM resources.
   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete \
     -f {{< release_source_url raw=true path=examples/multicluster/sock-shop/sock-shop-app.yaml >}}
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete \
     -f {{< release_source_url raw=true path=examples/multicluster/sock-shop/sock-shop-comp.yaml >}}
   ```

1. Delete the project.
   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete \
    -f {{< release_source_url raw=true path=examples/multicluster/sock-shop/verrazzano-project.yaml >}}
   ```

1. Delete the namespace `mc-sockshop` after the application pods are terminated.
   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete namespace mc-sockshop
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 delete namespace mc-sockshop
   ```
