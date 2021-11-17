
# Hello World Helidon

This example is a Helidon-based service that returns a “Hello World” response when invoked. The application configuration uses the default, microprofile properties file.

## Before you begin

Install Verrazzano by following the [installation]({{< relref "/docs/setup/install/installation.md" >}}) instructions.

**NOTE:** The Hello World Helidon example application deployment files are contained in the Verrazzano project located at `<VERRAZZANO_HOME>/examples/hello-helidon`, where `<VERRAZZANO_HOME>` is the root of the Verrazzano project.

## Deploy the Hello World Helidon application


1. Create a namespace for the application and add a label identifying the namespace as managed by Verrazzano.
   ```
   $ kubectl create namespace hello-helidon
   $ kubectl label namespace hello-helidon verrazzano-managed=true istio-injection=enabled
   ```

1. To deploy the application, apply the `hello-helidon` OAM resources.
   ```
   $ kubectl apply -f {{< release_source_url raw=true path=examples/hello-helidon/hello-helidon-comp.yaml >}}
   $ kubectl apply -f {{< release_source_url raw=true path=examples/hello-helidon/hello-helidon-app.yaml >}}
   ```

1. Wait for the application to be ready.
   ```
   $ kubectl wait \
      --for=condition=Ready pods \
      --all \
      -n hello-helidon \
      --timeout=300s
   ```

## Explore the application

The Hello World Helidon microservices application implements a REST API endpoint, `/greet`, which returns a message `{"message":"Hello World!"}` when invoked.

**NOTE**:  The following instructions assume that you are using a Kubernetes
environment such as OKE.  Other environments or deployments may require alternative mechanisms for retrieving addresses,
ports, and such.

Follow these steps to test the endpoints:

1. Get the generated host name for the application.

   ```
   $ HOST=$(kubectl get gateway hello-helidon-hello-helidon-appconf-gw \
        -n hello-helidon \
        -o jsonpath='{.spec.servers[0].hosts[0]}')
   $ echo $HOST
   
   # Sample output
   hello-helidon-appconf.hello-helidon.11.22.33.44.nip.io
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

1. Access the application:

   * **Using the command line**
     ```
     $ curl -sk \
        -X GET \
        https://${HOST}/greet \
        --resolve ${HOST}:443:${ADDRESS}
     
     # Expected response output
     {"message":"Hello World!"}
     ```
     If you are using `nip.io`, then you do not need to include `--resolve`.
   * **Local testing with a browser**

     Temporarily, modify the `/etc/hosts` file (on Mac or Linux)
     or `c:\Windows\System32\Drivers\etc\hosts` file (on Windows 10),
     to add an entry mapping the host name to the ingress gateway's `EXTERNAL-IP` address.
     Use the result of `$HOST` for the host name and `$ADDRESS` for the address.
     For example:
     ```
     11.22.33.44 hello-helidon-appconf.hello-helidon.11.22.33.44.nip.io
     ```
     Then you can access the application in a browser at `https://<host>/greet`.

   * **Using your own DNS name**
     * Point your own DNS name to the ingress gateway's `EXTERNAL-IP` address.
     * In this case, you would need to edit the `hello-helidon-app.yaml` file
       to use the appropriate value under the `hosts` section (such as `yourhost.your.domain`),
       before deploying the `hello-helidon` application.
     * Then, you can use a browser to access the application at `https://<yourhost.your.domain>/greet`.     

1. A variety of endpoints associated with the deployed application, are available to further explore the logs, metrics, and such.  

     Accessing them may require the following:

    - Run this command to get the password that was generated for the telemetry components:

      ```
      $ kubectl get secret \
         --namespace verrazzano-system verrazzano \
         -o jsonpath={.data.password} | base64 \
         --decode; echo
      ```
      The associated user name is `verrazzano`.

    - You will have to accept the certificates associated with the endpoints.

      You can retrieve the list of available ingresses with following command:

         ```
         $ kubectl get ingress -n verrazzano-system
      
         # Sample output
         NAME                    CLASS    HOSTS                                                 ADDRESS       PORTS     AGE
         verrazzano-ingress      <none>   verrazzano.default.11.22.33.44.nip.io                 11.22.33.44   80, 443   7d
         vmi-system-es-ingest    <none>   elasticsearch.vmi.system.default.11.22.33.44.nip.io   11.22.33.44   80, 443   7d
         vmi-system-grafana      <none>   grafana.vmi.system.default.11.22.33.44.nip.io         11.22.33.44   80, 443   7d
         vmi-system-kiali        <none>   kiali.vmi.system.default.11.22.33.44.nip.io           11.22.33.44   80, 443   7d
         vmi-system-kibana       <none>   kibana.vmi.system.default.11.22.33.44.nip.io          11.22.33.44   80, 443   7d
         vmi-system-prometheus   <none>   prometheus.vmi.system.default.11.22.33.44.nip.io      11.22.33.44   80, 443   7d
         ```  

         Using the ingress host information, some of the endpoints available are:

         | Description| Address | Credentials |
         | --- | --- | --- |
         | Kibana | `https://[vmi-system-kibana ingress host]` | `verrazzano`/`telemetry-password` |
         | Grafana | `https://[vmi-system-grafana ingress host]` | `verrazzano`/`telemetry-password` |
         | Prometheus | `https://[vmi-system-prometheus ingress host]` | `verrazzano`/`telemetry-password` |    
         | Kiali | `https://[vmi-system-kiali ingress host]` | `verrazzano`/`telemetry-password` |    


## Troubleshooting

1. Verify that the application configuration, domain, and ingress trait all exist.
   ```
   $ kubectl get ApplicationConfiguration -n hello-helidon
   $ kubectl get IngressTrait -n hello-helidon
   ```   

1. Verify that the `hello-helidon` service pods are successfully created and transition to the `READY` state.
   Note that this may take a few minutes and that you may see some of the services terminate and restart.
   ```
    $ kubectl get pods -n hello-helidon

    # Sample output
    NAME                                      READY   STATUS    RESTARTS   AGE
    hello-helidon-workload-676d97c7d4-wkrj2   2/2     Running   0          5m39s
   ```
## Undeploy the application

1. To undeploy the application, delete the Hello World Helidon OAM resources.
   ```
   $ kubectl delete -f {{< release_source_url raw=true path=examples/hello-helidon/hello-helidon-app.yaml >}}
   $ kubectl delete -f {{< release_source_url raw=true path=examples/hello-helidon/hello-helidon-comp.yaml >}}
   ```

1. Delete the namespace `hello-helidon` after the application pod is terminated.
   ```
   $ kubectl delete namespace hello-helidon
   ```
