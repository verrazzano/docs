
# Hello World Helidon

This example is a Helidon-based service that returns a “Hello World” response when invoked. The application configuration uses the default, microprofile properties file.

## Before you begin

Install Verrazzano by following the [installation]({{< relref "/docs/setup/install/" >}}) instructions.

**NOTE**: The Hello World Helidon example application deployment files are contained in the Verrazzano project located at `<VERRAZZANO_HOME>/examples/hello-helidon`, where `<VERRAZZANO_HOME>` is the root of the Verrazzano project.

## Deploy the Hello World Helidon application

{{< alert title="NOTE" color="primary" >}}To run this application in the default namespace:

   {{< clipboard >}}
   <div class="highlight">

   ```
   $ kubectl label namespace default verrazzano-managed=true istio-injection=enabled
   ```
   </div>
   {{< /clipboard >}}

   If you chose the default namespace, you can skip Step 1 and ignore the `-n` option in the rest of the commands.
{{< /alert >}}

1. To run the application in a namespace other than default namespace, create a namespace for the application and add a label identifying the namespace as managed by Verrazzano.

   {{< clipboard >}}
   <div class="highlight">

   ```
   $ kubectl create namespace hello-helidon
   $ kubectl label namespace hello-helidon verrazzano-managed=true istio-injection=enabled
   ```

   </div>
   {{< /clipboard >}}

1. To deploy the application, apply the `hello-helidon` OAM resources.

   {{< clipboard >}}
   <div class="highlight">

   ```
   $ kubectl apply -f {{< release_source_url raw=true path=examples/hello-helidon/hello-helidon-comp.yaml >}} -n hello-helidon
   $ kubectl apply -f {{< release_source_url raw=true path=examples/hello-helidon/hello-helidon-app.yaml >}} -n hello-helidon
   ```

   </div>
   {{< /clipboard >}}

1. Wait for the application to be ready.

   {{< clipboard >}}
   <div class="highlight">

   ```
   $ kubectl wait \
      --for=condition=Ready pods \
      --all \
      -n hello-helidon \
      --timeout=300s
   ```

   </div>
   {{< /clipboard >}}

## Explore the application

The Hello World Helidon microservices application implements a REST API endpoint, `/greet`, which returns a message `{"message":"Hello World!"}` when invoked.

**NOTE**:  The following instructions assume that you are using a Kubernetes
environment such as OKE.  Other environments or deployments may require alternative mechanisms for retrieving addresses,
ports, and such.

Follow these steps to test the endpoints.

1. Get the generated host name for the application.
   {{< clipboard >}}
   <div class="highlight">

   ```
   $ HOST=$(kubectl get gateways.networking.istio.io hello-helidon-hello-helidon-gw \
        -n hello-helidon \
        -o jsonpath='{.spec.servers[0].hosts[0]}')
   $ echo $HOST

   # Sample output
   hello-helidon-appconf.hello-helidon.11.22.33.44.nip.io
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

1. Access the application.

   * **Using the command line**
{{< clipboard >}}
<div class="highlight">

  ```
  $ curl -sk \
     -X GET \
     https://${HOST}/greet \
     --resolve ${HOST}:443:${ADDRESS}

  # Expected response output
  {"message":"Hello World!"}
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
     11.22.33.44 hello-helidon.example.com
     ```
     Then you can access the application in a browser at `https://<host>/greet`.

     - If you are using `nip.io`, then you can access the application in a browser using the `HOST` variable (for example, `https://${HOST}/greet`).  
     - If you are going through a proxy, then you may need to add `*.nip.io` to the `NO_PROXY` list.

   * **Using your own DNS name**

     Point your own DNS name to the ingress gateway's `EXTERNAL-IP` address.
     * In this case, you would need to edit the `hello-helidon-app.yaml` file
       to use the appropriate value under the `hosts` section (such as `yourhost.your.domain`),
       before deploying the `hello-helidon` application.
     * Then, you can use a browser to access the application at `https://<yourhost.your.domain>/greet`.     

1. A variety of endpoints associated with the deployed application are available to further explore the logs, metrics, and such.
You can access them according to the directions [here]({{< relref "/docs/access/#get-the-consoles-urls" >}}).  


## Troubleshooting

1. Verify that the application configuration, domain, and ingress trait all exist.
   {{< clipboard >}}
   <div class="highlight">

   ```
   $ kubectl get ApplicationConfiguration -n hello-helidon
   $ kubectl get IngressTrait -n hello-helidon
   ```

   </div>
   {{< /clipboard >}}  

1. Verify that the `hello-helidon` service pods are successfully created and transition to the `READY` state.
   Note that this may take a few minutes and that you may see some of the services terminate and restart.

   {{< clipboard >}}
   <div class="highlight">

   ```
    $ kubectl get pods -n hello-helidon

   # Sample output
    NAME                                      READY   STATUS    RESTARTS   AGE
    hello-helidon-workload-676d97c7d4-wkrj2   2/2     Running   0          5m39s
   ```

   </div>
   {{< /clipboard >}}

## Undeploy the application

1. To undeploy the application, delete the Hello World Helidon OAM resources.

   {{< clipboard >}}
   <div class="highlight">

   ```
   $ kubectl delete -f {{< release_source_url raw=true path=examples/hello-helidon/hello-helidon-app.yaml >}} -n hello-helidon
   $ kubectl delete -f {{< release_source_url raw=true path=examples/hello-helidon/hello-helidon-comp.yaml >}} -n hello-helidon
   ```
   </div>
   {{< /clipboard >}}

1. Delete the namespace `hello-helidon` after the application pod is terminated.


   {{< clipboard >}}
   <div class="highlight">

   ```
   $ kubectl delete namespace hello-helidon
   ```
   </div>
   {{< /clipboard >}}
